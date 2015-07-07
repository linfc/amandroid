/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.cli

import org.sireum.option.SireumAmandroidTaintAnalysisMode
import org.sireum.util._
import org.sireum.option.AnalyzeSource
import org.sireum.jawa.util.APKFileResolver
import java.io.File
import org.sireum.jawa.JawaCodeSource
import org.sireum.amandroid.libPilarFiles.AndroidLibPilarFiles
import org.sireum.util.FileResourceUri
import java.io.PrintWriter
import org.sireum.amandroid.alir.dataRecorder.MetricRepo
import org.sireum.amandroid.alir.dataRecorder.DataCollector
import org.sireum.jawa.Center
import org.sireum.jawa.ClassLoadManager
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.AndroidRFAConfig
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysis
import org.sireum.amandroid.appInfo.AppInfoCollector
import org.sireum.jawa.alir.dataDependenceAnalysis.InterproceduralDataDependenceAnalysis
import org.sireum.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis
import java.net.URI
import org.sireum.amandroid.decompile.Dex2PilarConverter
import org.sireum.jawa.MessageCenter._
import org.sireum.jawa.MessageCenter
import org.sireum.amandroid.util.AndroidLibraryAPISummary
import org.sireum.amandroid.alir.taintAnalysis.DefaultAndroidSourceAndSinkManager
import org.sireum.amandroid.AndroidConstants
import org.sireum.amandroid.AndroidGlobalConfig
import org.sireum.amandroid.AppCenter
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.sireum.jawa.alir.LibSideEffectProvider
import org.sireum.jawa.GlobalConfig
import org.sireum.amandroid.security.AmandroidSocket
import org.sireum.amandroid.security.AmandroidSocketListener
import org.sireum.jawa.util.IgnoreException
import org.sireum.option.MessageLevel
import org.sireum.amandroid.cli.util.CliLogger
import org.sireum.jawa.util.MyTimer
import org.sireum.jawa.util.MyTimeoutException

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */
object TaintAnalyzeCli {
  private final val TITLE = "TaintAnalyzeCli"
	def run(saamode: SireumAmandroidTaintAnalysisMode) {
    val sourceType = saamode.general.typ
    val sourceDir = saamode.srcFile
    val sourceFile = new File(sourceDir)
    val sasDir = saamode.sasFile
    val outputDir = saamode.analysis.outdir
    val nostatic = saamode.analysis.noStatic
    val parallel = saamode.analysis.parallel
    val noicc = saamode.analysis.noicc
    val k_context = saamode.analysis.k_context
    val timeout = saamode.analysis.timeout
    val mem = saamode.general.mem
    val msgLevel = saamode.general.msgLevel
    forkProcess(nostatic, parallel, noicc, k_context, timeout, sourceType, sourceDir, sasDir, outputDir, mem, msgLevel)
  }
	
	def forkProcess(nostatic: Boolean, parallel: Boolean, noicc: Boolean, k_context: Int, timeout: Int, typSpec: AnalyzeSource.Type, sourceDir: String, sasDir: String, outputDir: String, mem: Int, msgLevel: MessageLevel.Type) = {
	  val args: MList[String] = mlistEmpty
	  args += "-s"
	  args += (!nostatic).toString
	  args += "-par"
	  args += parallel.toString
	  args += "-i"
	  args += (!noicc).toString
	  args += "-k"
	  args += k_context.toString
	  args += "-to"
	  args += timeout.toString
	  args += "-msg"
	  args += msgLevel.toString
	  args ++= List("-t", typSpec.toString, sourceDir, sasDir, outputDir)
    org.sireum.jawa.util.JVMUtil.startSecondJVM(TanitAnalysis.getClass(), "-Xmx" + mem + "G", args.toList, true)
  }
}

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */ 
object TanitAnalysis{
  private final val TITLE = "TaintAnalysis"
  def main(args: Array[String]) {
	  if(args.size != 17){
	    println("Usage: -s [handle static init] -par [parallel] -i [handle icc] -k [k context] -to [timeout minutes] -msg [Message Level: NO, CRITICAL, NORMAL, VERBOSE] -t type[allows: APK, DIR] <source path> <Sink list file path> <output path>")
	    return
	  }
	  
	  val static = args(1).toBoolean
	  val parallel = args(3).toBoolean
	  val icc = args(5).toBoolean
	  val k_context = args(7).toInt
	  val timeout = args(9).toInt
	  val msgLevel = args(11)
	  val typ = args(13)
	  val sourcePath = args(14)
	  val sasFilePath = args(15)
	  val outputPath = args(16)
	  
	  msgLevel match{
	    case "NO$" =>
	      MessageCenter.msglevel = MessageCenter.MSG_LEVEL.NO
	    case "CRITICAL$" =>
	      MessageCenter.msglevel = MessageCenter.MSG_LEVEL.CRITICAL
	    case "NORMAL$" =>
	      MessageCenter.msglevel = MessageCenter.MSG_LEVEL.NORMAL
	    case "VERBOSE$" =>
	      MessageCenter.msglevel = MessageCenter.MSG_LEVEL.VERBOSE
      case _ => 
        println("Unexpected msg level: " + msgLevel)
        return
	  }
	  
	  val apkFileUris = typ match{
      case "APK$" =>
        require(sourcePath.endsWith(".apk"))
        Set(FileUtil.toUri(sourcePath))
      case "DIR$" =>
        require(new File(sourcePath).isDirectory())
        FileUtil.listFiles(FileUtil.toUri(sourcePath), ".apk", true).toSet
      case _ => 
        println("Unexpected type: " + typ)
        return
    }
		taintAnalyze(apkFileUris, sasFilePath, outputPath, static, parallel, icc, k_context, timeout)
	}
  
  def taintAnalyze(apkFileUris: Set[FileResourceUri], sasFilePath: String, outputPath: String, static: Boolean, parallel: Boolean, icc: Boolean, k_context: Int, timeout: Int) = {
    AndroidGlobalConfig.SourceAndSinkFilePath = sasFilePath
    GlobalConfig.ICFG_CONTEXT_K = k_context
    AndroidReachingFactsAnalysisConfig.parallel = parallel
    AndroidReachingFactsAnalysisConfig.resolve_icc = icc
    AndroidReachingFactsAnalysisConfig.resolve_static_init = static
//    AndroidReachingFactsAnalysisConfig.timeout = timeout
    println("Total apks: " + apkFileUris.size)
    

    try{
      val socket = new AmandroidSocket
      socket.preProcess
      
      var i: Int = 0
      
      apkFileUris.foreach{
        file =>
          i += 1
          try{
            msg_critical(TITLE, "Analyzing #" + i + ":" + file)
            msg_critical(TITLE, TaintTask(outputPath, file, socket, parallel, Some(timeout*60)).run)   
          } catch {
            case te: MyTimeoutException => err_msg_critical(TITLE, te.message)
            case e: Throwable =>
              CliLogger.logError(new File(outputPath), "Error: " , e)
          } finally{
            socket.cleanEnv
          }
      }
    } catch {
      case e: Throwable => 
        CliLogger.logError(new File(outputPath), "Error: " , e)

    }
	  
	}
  
  private case class TaintTask(outputPath: String, file: FileResourceUri, socket: AmandroidSocket, parallel: Boolean, timeout: Option[Int]) {
    def run: String = {
      val timer = timeout match {
        case Some(t) => Some(new MyTimer(t))
        case None => None
      }
      if(timer.isDefined) timer.get.start
      val outUri = socket.loadApk(file, outputPath, AndroidLibraryAPISummary)
      val app_info = new AppInfoCollector(file, outUri, timer)
      app_info.collectInfo
      val ssm = new DefaultAndroidSourceAndSinkManager(app_info.getPackageName, app_info.getLayoutControls, app_info.getCallbackMethods, AndroidGlobalConfig.SourceAndSinkFilePath)
      socket.plugListener(new TaintListener(file, outputPath, app_info))
      socket.runWithDDA(ssm, false, parallel, timer)
      return "Done!"
    }
  }
  
  private class TaintListener(source_apk: FileResourceUri, output_dir: String, app_info: AppInfoCollector) extends AmandroidSocketListener {
    def onPreAnalysis: Unit = {
    }

    def entryPointFilter(eps: Set[org.sireum.jawa.JawaMethod]): Set[org.sireum.jawa.JawaMethod] = {
      eps
    }

    def onTimeout: Unit = {
      System.err.println("Timeout!")
      savePartialResults()
    }

    def onAnalysisSuccess: Unit = {
      msg_critical(TITLE, "Saving results of Taint Analysis ...") 
      saveResults();
    }
    

    def onPostAnalysis: Unit = {
    }
    
    def onException(e: Exception): Unit = {
      e match{
        case ie: IgnoreException => System.err.println("Ignored!")
        case a => 
          CliLogger.logError(new File(output_dir), "Error: " , e)
      }
      savePartialResults();
    }
    
    def savePartialResults() = {
      msg_critical(TITLE, "Saving partial results of Taint Analysis ...")
      saveResults();
    }
    
    def saveResults() = {
      val appData = DataCollector.collect
      MetricRepo.collect(appData)

      val apkName = source_apk.substring(source_apk.lastIndexOf("/"), source_apk.lastIndexOf("."))
      val appDataDirFile = new File(output_dir + "/" + apkName)
      if(!appDataDirFile.exists()) appDataDirFile.mkdirs()
      
      val environmentModel = new PrintWriter(appDataDirFile + "/EnvironmentModel.txt")
      val envString = app_info.getEnvString
      environmentModel.print(envString)
      environmentModel.close()
      
      val analysisResult = new PrintWriter(appDataDirFile + "/TaintResult.txt")
      analysisResult.print(appData.toString)
      analysisResult.close()
    }
  }
  
}