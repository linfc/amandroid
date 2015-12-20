/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.cli

import org.sireum.option.SireumAmandroidDecompileMode
import org.sireum.jawa.util.APKFileResolver
import org.sireum.util._
import java.io.File
import java.net.URI
import org.sireum.amandroid.cli.util.CliLogger
import org.sireum.amandroid.decompile.Dex2PilarConverter
import brut.androlib.ApkDecoder
import org.sireum.amandroid.decompile.AmDecoder
import org.sireum.amandroid.util.ApkFileUtil
import org.sireum.amandroid.decompile.ApkDecompiler
import org.sireum.amandroid.Apk
import org.sireum.amandroid.AndroidGlobalConfig

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */
object DecompilerCli {
	def run(sadmode: SireumAmandroidDecompileMode) {
    val mem = sadmode.general.mem
    val debug = sadmode.general.debug
    val sourceDir = sadmode.srcFile
    val sourceFile = new File(sourceDir)
    val outputDirOpt = if(sadmode.outFile == "") None else Some(sadmode.outFile)
    val outputDir = outputDirOpt match{
	    case Some(path) => path
	    case None => sourceFile.getParent()
	  }
    forkProcess(mem, debug, sourceDir, outputDir)
  }
	
	def forkProcess(mem: Int, debug: Boolean, sourceDir: String, outputDir: String) = {
	  val args = List(debug.toString, sourceDir, outputDir)
    org.sireum.jawa.util.JVMUtil.startSecondJVM(Decompiler.getClass(), "-Xmx" + mem + "G", args, true)
  }
  
//  def main(args: Array[String]): Unit = {
//    org.sireum.jawa.util.JVMUtil.startSecondJVM(Decompiler.getClass(), "-Xmx4G", List(), true)
//  }
}

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */ 
object Decompiler {
	def main(args: Array[String]) {
	  if(args.size != 3){
	    println("Usage: <debug> <source path> <output path>")
	    return
	  }
	  val debug = args(0).toBoolean
	  val sourcePath = args(1)
	  val outputPath = args(2)
    val dpsuri = AndroidGlobalConfig.dependence_dir.map(FileUtil.toUri(_))
	  val outputUri = FileUtil.toUri(outputPath)
<<<<<<< HEAD
    
	  val fileUris : MSet[(FileResourceUri, FileResourceUri)] = msetEmpty
    typ match{
      case "APK" =>
        require(sourcePath.endsWith(".apk"))
        val out = AmDecoder.decode(FileUtil.toUri(sourcePath), outputUri)
        fileUris += ((FileUtil.toUri(sourcePath), out + "classes"))
      case "DIR" =>
        require(new File(sourcePath).isDirectory())
        val apkFileUris = FileUtil.listFiles(FileUtil.toUri(sourcePath), ".apk", true).toSet
        apkFileUris.map{
		      apkFileUri=>
		        val out = AmDecoder.decode(apkFileUri, outputUri)
            fileUris += ((apkFileUri, out + "classes"))
		    }
      case "DEX" =>
        require(sourcePath.endsWith(".dex") || sourcePath.endsWith(".odex"))
        fileUris += ((FileUtil.toUri(sourcePath), outputUri))
      case _ => 
        println("Unexpected type: " + typ)
        return
    }
    decompile(fileUris.toSet, outputPath)
  }
  
	def decompile(fileUris : Set[(FileResourceUri, FileResourceUri)], outputPath : String) = {
    fileUris.foreach{
      case (apkFileUri, outUri) =>
        try{
          if(FileUtil.toFile(apkFileUri).exists())
            Dex2PilarConverter.convert(apkFileUri, outUri)
        } catch {
          case e : Throwable =>
            CliLogger.logError(new File(outputPath), "Error: " , e)
        }
    }
	}
=======

	  val fileUris: MSet[(FileResourceUri, FileResourceUri)] = msetEmpty
    try {
      val fileOrDir = new File(sourcePath)
      fileOrDir match {
        case dir if dir.isDirectory() =>
          val apks = ApkFileUtil.getApks(FileUtil.toUri(dir), true)
          val dexs = FileUtil.listFiles(FileUtil.toUri(dir), "dex", true)
          println(s"Processing directory which contains ${if(apks.size > 0) s"${apks.size} apk${if(apks.size > 1) "s" else ""}" else ""} ${if(dexs.size > 0) s"${dexs.size} dex${if(dexs.size > 1) "s" else ""}" else ""}")
          apks.foreach {
            apkUri =>
              println("####" + apkUri + "####")
              ApkDecompiler.decompile(FileUtil.toFile(apkUri), FileUtil.toFile(outputUri), dpsuri, false, false, true, true)
              println("Done!")
          }
          dexs.foreach {
            dexUri =>
              println("####" + dexUri + "####")
              val dexname = dexUri.substring(dexUri.lastIndexOf("/") + 1, dexUri.lastIndexOf("."))
              ApkDecompiler.decompileDex(dexUri, outputUri + "/" + dexname, dpsuri, "", false, false, false, true)
              println("Done!")
          }
        case file =>
          println("Processing " + file)
          if(Apk.isValidApk(FileUtil.toUri(file)))
            ApkDecompiler.decompile(file, FileUtil.toFile(outputUri), dpsuri, false, false, true, true)
          else if(file.getName.endsWith(".dex")) ApkDecompiler.decompileDex(FileUtil.toUri(file), outputUri, dpsuri, "", false, false, false, true)
          else println(file + " is not decompilable.")
      }
    } catch {
      case e: Exception => 
        CliLogger.logError(new File(sourcePath), "Error: " , e)
    }
  }
>>>>>>> upstream/master
}