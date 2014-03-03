package org.sireum.amandroid.test.security

import org.junit.runner.RunWith
import org.sireum.amandroid.test.framework.security.ICCTestFramework
import org.scalatest.junit.JUnitRunner
import org.sireum.amandroid.alir.AndroidGlobalConfig
import org.sireum.jawa.JawaCodeSource
import java.util.zip.GZIPInputStream
import org.sireum.amandroid.android.libPilarFiles.AndroidLibPilarFiles
import java.io.FileInputStream
import org.sireum.jawa.xml.AndroidXStream
import org.sireum.jawa.alir.interProcedural.sideEffectAnalysis.InterProceduralSideEffectAnalysisResult
import org.sireum.amandroid.example.interprocedural.InterproceduralExamples
import org.sireum.jawa.alir.LibSideEffectProvider

@RunWith(classOf[JUnitRunner])
class IccTest extends ICCTestFramework {
  var i = 0
  val androidLibDir = System.getenv(AndroidGlobalConfig.ANDROID_LIB_DIR)
  if(androidLibDir != null){
		JawaCodeSource.preLoad(AndroidLibPilarFiles.pilarModelFiles(androidLibDir).toSet)
		
		LibSideEffectProvider.init
		
//	  InterproceduralExamples.testAPKFiles.
//	  filter { s => s.endsWith("PasswordPassTest.apk") }.
//	  foreach { resfile =>
//	    Analyzing title resfile file (resfile, interPSEA)
//	  }
//	  InterproceduralExamples.popularAPKFiles.
//	  filter { s => s.contains("mobi.mgeek.TunnyBrowser.apk") }.
//	  foreach { resfile =>
////	    if(i > 500) 
//	    Analyzing title resfile file resfile
//	    i+=1
//	  }
//		InterproceduralExamples.testFiles.
////	  filter { s => s.endsWith("acctsvcs.us.apk")}.
//	  foreach { resfile =>
////	    if(i < 10) 
//	    Analyzing title resfile file resfile
////	    i+=1
//	  }
	  InterproceduralExamples.randomAPKFiles.
//	  filter { s => s.endsWith("gtd.client.apk") }.
	  foreach { resfile =>
//	    if(i < 89) i += 1
	    //if(resfile.endsWith("app.kazoebito.com.apk"))
	    Analyzing title resfile file resfile
	  }
//	  InterproceduralExamples.normalAPKFiles.
//	//  filter { s => s.name.endsWith("android-1.apk") }.
//	  foreach { resRet =>
//	//    if(i < 37) i += 1
//	    Analyzing title resRet.name file resRet
//	  }
//	  InterproceduralExamples.maliciousAPKRets.
//	//  filter { s => s.name.endsWith("86add.apk")}.
//	  foreach { resRet =>
//	//    if(i < 7) i += 1
//	    Analyzing title resRet.name file resRet
//	  }
//	  InterproceduralExamples.maliciousArborFiles.
////	  filter { s => s.endsWith("6ba36c93.apk")}.
//	  foreach { resfile =>
////	    if(i < 10) 
//	    Analyzing title resfile file (resfile, interPSEA)
////	    i+=1
//	  }
//	  InterproceduralExamples.benchAPKFiles.
//	  filter { s => s.endsWith("PrivateDataLeak2.apk") }.
//	  foreach { fileUri =>
//	    Analyzing title fileUri file fileUri
//	  }
//		InterproceduralExamples.benchExtendAPKFiles.
//	  filter { s => s.contains("InterComponentCommunication_DynRegister") }.
//	  foreach { fileUri =>
//	    Analyzing title fileUri file fileUri
//	  }
  } else {
    System.err.println("Does not have env var: " + AndroidGlobalConfig.ANDROID_LIB_DIR)
  }
}