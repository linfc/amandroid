package org.sireum.amandroid.security.cli

import org.sireum.option.SireumAmandroidPasswordTrackingMode
import org.sireum.option.AnalyzeSource
import java.io.File
import org.sireum.jawa.MessageCenter
import org.sireum.util._
import org.sireum.jawa.JawaCodeSource
import org.sireum.amandroid.android.libPilarFiles.AndroidLibPilarFiles
import java.net.URI
import org.sireum.jawa.util.APKFileResolver
import org.sireum.amandroid.android.decompile.Dex2PilarConverter
import org.sireum.jawa.Center
import org.sireum.amandroid.alir.interProcedural.reachingFactsAnalysis.AndroidRFAConfig
import org.sireum.amandroid.android.util.AndroidLibraryAPISummary
import org.sireum.amandroid.alir.AndroidConstants
import org.sireum.amandroid.alir.AndroidGlobalConfig
import org.sireum.amandroid.alir.AppCenter
import org.sireum.amandroid.android.appInfo.AppInfoCollector
import org.sireum.amandroid.security.password.SensitiveViewCollector
import org.sireum.amandroid.security.password.PasswordSourceAndSinkManager
import org.sireum.amandroid.alir.interProcedural.reachingFactsAnalysis.AndroidReachingFactsAnalysis
import org.sireum.jawa.ClassLoadManager
import org.sireum.jawa.util.Timer
import org.sireum.jawa.alir.interProcedural.dataDependenceAnalysis.InterproceduralDataDependenceAnalysis
import org.sireum.amandroid.alir.interProcedural.taintAnalysis.AndroidDataDependentTaintAnalysis
import org.sireum.amandroid.alir.dataRecorder.DataCollector
import org.sireum.jawa.util.IgnoreException
import java.io.PrintWriter
import org.sireum.amandroid.alir.interProcedural.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.sireum.jawa.alir.LibSideEffectProvider
import org.sireum.jawa.util.TimeOutException

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */
object PasswordTrackingCli {
	def run(saamode : SireumAmandroidPasswordTrackingMode) {
    val sourceType = saamode.general.typ match{
      case AnalyzeSource.APK => "APK"
      case AnalyzeSource.DIR => "DIR"}
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
    val libSideEffectPath = saamode.analysis.sideeffectPath
    forkProcess(nostatic, parallel, noicc, k_context, timeout, sourceType, sourceDir, sasDir, outputDir, mem, libSideEffectPath)
    println("Generated environment-model and analysis results are saved in: " + outputDir)
  }
	
	def forkProcess(nostatic : Boolean, parallel : Boolean, noicc : Boolean, k_context : Int, timeout : Int, typSpec : String, sourceDir : String, sasDir : String, outputDir : String, mem : Int, libSideEffectPath : String) = {
	  val args : MList[String] = mlistEmpty
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
	  args ++= List("-t", typSpec, "-ls", libSideEffectPath, sourceDir, sasDir, outputDir)
    org.sireum.jawa.util.JVMUtil.startSecondJVM(PasswordTracking.getClass(), "-Xmx" + mem + "G", args.toList, true)
  }
}

object PasswordTracking {
	def main(args: Array[String]) {
	  if(args.size != 17){
	    println("Usage: -s [handle static init] -par [parallel] -i [handle icc] -k [k context] -to [timeout minutes] -t type[allows: APK, DIR] -ls [Lib-SideEffect-Path] <source path> <Sink list file path> <output path>")
	    return
	  }
	  MessageCenter.msglevel = MessageCenter.MSG_LEVEL.NO
	  val static = args(1).toBoolean
	  val parallel = args(3).toBoolean
	  val icc = args(5).toBoolean
	  val k_context = args(7).toInt
	  val timeout = args(9).toInt
	  val typ = args(11)
	  val libSideEffectPath = args(13)
	  val sourcePath = args(14)
	  val sasFilePath = args(15)
	  val outputPath = args(16)
	  val apkFileUris = typ match{
      case "APK" =>
        require(sourcePath.endsWith(".apk"))
        Set(FileUtil.toUri(sourcePath))
      case "DIR" =>
        require(new File(sourcePath).isDirectory())
        FileUtil.listFiles(FileUtil.toUri(sourcePath), ".apk", true).toSet
      case _ => 
        println("Unexpected type: " + typ)
        return
    }
	  val outputUri = FileUtil.toUri(outputPath)
    val androidLibDir = System.getenv(AndroidGlobalConfig.ANDROID_LIB_DIR)
	  if(androidLibDir != null){
			JawaCodeSource.preLoad(AndroidLibPilarFiles.pilarModelFiles(androidLibDir).toSet)	
			passwordTracking(apkFileUris, sasFilePath, libSideEffectPath, outputUri, static, parallel, icc, k_context, timeout)
	  } else {
	    throw new RuntimeException("Does not have environment variable: " + AndroidGlobalConfig.ANDROID_LIB_DIR)
	  }
	}
  
  def passwordTracking(apkFileUris : Set[FileResourceUri], sasFilePath : String, libSideEffectPath : String, outputUri : FileResourceUri, static : Boolean, parallel : Boolean, icc : Boolean, k_context : Int, timeout : Int) = {
    AndroidGlobalConfig.SourceAndSinkFilePath = sasFilePath
    if(libSideEffectPath != ""){
    	LibSideEffectProvider.init(libSideEffectPath)
    }
    AndroidReachingFactsAnalysisConfig.k_context = k_context
    AndroidReachingFactsAnalysisConfig.parallel = parallel
    AndroidReachingFactsAnalysisConfig.resolve_icc = icc
    AndroidReachingFactsAnalysisConfig.resolve_static_init = static
    AndroidReachingFactsAnalysisConfig.timerOpt = Some(new Timer(timeout))
	  apkFileUris.foreach{
	    apkFileUri =>
	      println("Analyzing " + apkFileUri)
	      // before starting the analysis of the current app, first reset the Center which may still hold info (of the resolved records) from the previous analysis
	    	AndroidGlobalConfig.initJawaAlirInfoProvider
	      val apkFile = new File(new URI(apkFileUri))
	      val dexFileUri = APKFileResolver.getDexFile(apkFileUri, outputUri)
	      val pilarFileUri = Dex2PilarConverter.convert(dexFileUri)
		 
		  	val pilarFile = new File(new URI(pilarFileUri))

		  	if(pilarFile.length() <= (50 * 1024 * 1024)){
		  		AndroidRFAConfig.setupCenter
		    	//store the app's pilar code in AmandroidCodeSource which is organized record by record.
		    	JawaCodeSource.load(pilarFileUri, AndroidLibraryAPISummary)
		    	try{
			    	// resolve each record of the app and stores the result in the Center which will be available throughout the analysis.
			    	val pre = new SensitiveViewCollector(apkFileUri)
					  pre.collectInfo

					  val ssm = new PasswordSourceAndSinkManager(pre.getPackageName, pre.getLayoutControls, pre.getCallbackMethods, AndroidGlobalConfig.SourceAndSinkFilePath)
			    	var entryPoints = Center.getEntryPoints(AndroidConstants.MAINCOMP_ENV)
			    	entryPoints ++= Center.getEntryPoints(AndroidConstants.COMP_ENV)
			    	entryPoints = entryPoints.filter(e=>pre.getSensitiveLayoutContainers.contains(e.getDeclaringRecord))
			    	(if(parallel) entryPoints.par else entryPoints).foreach{
			    	  ep =>
			    	    try{
				    	    val initialfacts = AndroidRFAConfig.getInitialFactsForMainEnvironment(ep)
				    	    val (icfg, irfaResult) = AndroidReachingFactsAnalysis(ep, initialfacts, new ClassLoadManager)
				    	    AppCenter.addInterproceduralReachingFactsAnalysisResult(ep.getDeclaringRecord, icfg, irfaResult)
				    	    val iddResult = InterproceduralDataDependenceAnalysis(icfg, irfaResult)
				    	    AppCenter.addInterproceduralDataDependenceAnalysisResult(ep.getDeclaringRecord, iddResult)
				    	    val tar = AndroidDataDependentTaintAnalysis(iddResult, irfaResult, ssm)
				    	    AppCenter.addTaintAnalysisResult(ep.getDeclaringRecord, tar)
				    	  } catch {
			    	      case te : TimeOutException => System.err.println("Timeout!")
			    	    }
			    	}
			    	val appData = DataCollector.collect

			    	val apkName = apkFile.getName().substring(0, apkFile.getName().lastIndexOf("."))
			    	val opd = new File(new URI(outputUri))
			    	val appDataDirFile = new File(opd + "/" + apkName)
			    	if(!appDataDirFile.exists()) appDataDirFile.mkdirs()
			    	
			    	val environmentModel = new PrintWriter(appDataDirFile + "/EnvironmentModel.txt")
			    	val envString = pre.getEnvString
				    environmentModel.print(envString)
				    environmentModel.close()
			    	
			    	val analysisResult = new PrintWriter(appDataDirFile + "/PasswordTrackingResult.txt")
				    analysisResult.print(appData.toString)
				    analysisResult.close()
		    	} catch {
		    	  case ie : IgnoreException =>
		    	    println("No password view!")
		    	  case re : RuntimeException => 
		    	    re.printStackTrace()
		    	  case e : Exception =>
		    	    e.printStackTrace()
		    	} finally {
		    	}
		  	} else {
	    	  println("Pilar file size is too large:" + pilarFile.length()/1024/1024 + "MB")
	    	}
	      Center.reset
	    	AppCenter.reset
	    	JawaCodeSource.clearAppRecordsCodes
		  	System.gc()
			  System.gc()
			  println("Done!")
	  }
	  
	}
}