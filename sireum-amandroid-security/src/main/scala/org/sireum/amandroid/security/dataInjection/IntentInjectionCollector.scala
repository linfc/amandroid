/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.security.dataInjection

import org.sireum.util._
import org.sireum.amandroid.appInfo.AppInfoCollector
import org.sireum.jawa.util.IgnoreException
import org.sireum.jawa.JawaClass
import org.sireum.amandroid.AndroidConstants
import org.sireum.amandroid.appInfo.ReachableInfoCollector
import org.sireum.jawa.util.MyTimer
import org.sireum.jawa.Global
import org.sireum.amandroid.Apk
import java.io.File
import org.sireum.amandroid.parser.ComponentType

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class IntentInjectionCollector(global: Global, timer: Option[MyTimer]) extends AppInfoCollector(global, timer) {
  private final val TITLE = "IntentInjectionCollector"
<<<<<<< HEAD
  var ra : ReachableInfoCollector = null
	def getInterestingContainers(interestingAPIs : Set[String]) = {
	  var interestingContainers : Set[JawaClass] = Set()
=======
  var ra: ReachableInfoCollector = null
  def getInterestingContainers(interestingAPIs: Set[String]) = {
    var interestingContainers: Set[JawaClass] = Set()
>>>>>>> upstream/master
    interestingAPIs.foreach{
      api =>
        interestingContainers ++= this.ra.getSensitiveAPIContainer(api)
    }
    if(interestingContainers.isEmpty) throw new IgnoreException
    interestingContainers
  }
  
<<<<<<< HEAD
	override def collectInfo : Unit = {
	  val manifestUri = outputUri + "/AndroidManifest.xml"
    val mfp = AppInfoCollector.analyzeManifest(manifestUri)
	  this.appPackageName = mfp.getPackageName
		this.componentInfos ++= mfp.getComponentInfos
		this.uses_permissions ++= mfp.getPermissions
		this.intentFdb.merge(mfp.getIntentDB)
		
	  val afp = AppInfoCollector.analyzeARSC(apkUri)
		val lfp = AppInfoCollector.analyzeLayouts(apkUri, mfp)
<<<<<<< HEAD
		this.layoutControls ++= lfp.getUserControls
=======
		this.layoutControls = lfp.getUserControls
>>>>>>> CommunicationLeakage
		this.ra = AppInfoCollector.reachabilityAnalysis(mfp, timer)
		val callbacks = AppInfoCollector.analyzeCallback(afp, lfp, ra)
		this.callbackMethods ++= callbacks
		var components = isetEmpty[JawaClass]
    mfp.getComponentInfos.foreach{
      f => 
        val record = Center.resolveClass(f.name, Center.ResolveLevel.HIERARCHY)
        if(!record.isUnknown && record.isApplicationClass){
	        components += record
	        val clCounter = generateEnvironment(record, if(f.exported)AndroidConstants.MAINCOMP_ENV else AndroidConstants.COMP_ENV, codeLineCounter)
	        codeLineCounter = clCounter
=======
  override def collectInfo(apk: Apk, outputUri: FileResourceUri): Unit = {
  val manifestUri = outputUri + File.separator + "AndroidManifest.xml"
    val mfp = AppInfoCollector.analyzeManifest(global.reporter, manifestUri)
    this.appPackageName = mfp.getPackageName
    this.componentInfos ++= mfp.getComponentInfos
    this.uses_permissions ++= mfp.getPermissions
    this.intentFdb.merge(mfp.getIntentDB)

    val afp = AppInfoCollector.analyzeARSC(global.reporter, apk.nameUri)
    val lfp = AppInfoCollector.analyzeLayouts(global, apk.nameUri, mfp)
    this.layoutControls ++= lfp.getUserControls
    this.ra = AppInfoCollector.reachabilityAnalysis(global, mfp, timer)
    val callbacks = AppInfoCollector.analyzeCallback(global.reporter, afp, lfp, ra)
    this.callbackMethods ++= callbacks
    val components = msetEmpty[(JawaClass, ComponentType.Value)]
    mfp.getComponentInfos.foreach {
      f => 
        val record = global.getClassOrResolve(f.compType)
        if(!record.isUnknown && record.isApplicationClass){
          components += ((record, f.typ))
          val clCounter = generateEnvironment(record, if(f.exported)AndroidConstants.MAINCOMP_ENV else AndroidConstants.COMP_ENV, codeLineCounter)
          codeLineCounter = clCounter
>>>>>>> upstream/master
        }
    }

    apk.setComponents(components.toSet)
    apk.updateIntentFilterDB(this.intentFdb)
    apk.setAppInfo(this)
  }
}