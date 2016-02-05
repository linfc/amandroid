/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid

import org.sireum.util._
import org.sireum.jawa.JawaClass
import org.sireum.jawa.alir.controlFlowGraph._
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.sireum.jawa.alir.dataDependenceAnalysis.InterproceduralDataDependenceInfo
import org.sireum.amandroid.parser.IntentFilterDataBase
import org.sireum.amandroid.appInfo.AppInfoCollector
import org.sireum.jawa.alir.pta.PTAResult
import org.sireum.jawa.io.NoPosition
import org.sireum.jawa.JawaMethod
import org.sireum.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.sireum.jawa.alir.dataFlowAnalysis.InterProceduralDataFlowGraph
import org.sireum.jawa.alir.interProcedural.InterProceduralNode
import org.sireum.alir.AlirEdge
import java.util.zip.ZipInputStream
import java.io.FileInputStream
import java.util.zip.ZipEntry
import org.sireum.amandroid.parser.ComponentType

object Apk {
  def isValidApk(nameUri: FileResourceUri): Boolean = {
    class FindManifest extends Exception
    val file = FileUtil.toFile(nameUri)
    file match {
      case dir if dir.isDirectory() => false
      case _ => 
        var valid: Boolean = false
        var archive : ZipInputStream = null
        try {
          archive = new ZipInputStream(new FileInputStream(file))
          var entry: ZipEntry = null
          entry = archive.getNextEntry()
          while (entry != null) {
            val entryName = entry.getName()
            if(entryName == "AndroidManifest.xml"){
              valid = true
              throw new FindManifest 
            }
            entry = archive.getNextEntry()
          }
        } catch {
          case e: Exception =>
        } finally {
          if (archive != null)
            archive.close()
        }
        valid
    }
  }
}


/**
 * this is an object, which hold information of apps. e.g. components, intent-filter database, etc.
 *
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a> 
 */
case class Apk(nameUri: FileResourceUri) {
  import Apk._
  require(isValidApk(nameUri))
  private final val TITLE = "Apk"
  private val activities: MSet[JawaClass] = msetEmpty
  private val services: MSet[JawaClass] = msetEmpty
  private val receivers: MSet[JawaClass] = msetEmpty
  private val providers: MSet[JawaClass] = msetEmpty
  	
	private val dynamicRegisteredReceivers: MSet[JawaClass] = msetEmpty
	
	private val intentFdb: IntentFilterDataBase = new IntentFilterDataBase()
	
  private val rpcMethods: MMap[JawaClass, MSet[JawaMethod]] = mmapEmpty
  
	def addActivity(activity: JawaClass) = this.synchronized{this.activities += activity}
  def addService(service: JawaClass) = this.synchronized{this.services += service}
  def addReceiver(receiver: JawaClass) = this.synchronized{this.receivers += receiver}
  def addProvider(provider: JawaClass) = this.synchronized{this.providers += provider}
  
  def addRpcMethod(comp: JawaClass, rpc: JawaMethod) = rpcMethods.getOrElseUpdate(comp, msetEmpty) += rpc
  def addRpcMethods(comp: JawaClass, rpcs: ISet[JawaMethod]) = rpcMethods.getOrElseUpdate(comp, msetEmpty) ++= rpcs
  def getRpcMethods(comp: JawaClass): ISet[JawaMethod] = rpcMethods.getOrElse(comp, msetEmpty).toSet
  def getRpcMethods: ISet[JawaMethod] = rpcMethods.flatMap(_._2).toSet
	
  def getComponentType(comp: JawaClass): Option[AndroidConstants.CompType.Value] = {
    if(activities.contains(comp)) Some(AndroidConstants.CompType.ACTIVITY)
    else if(services.contains(comp)) Some(AndroidConstants.CompType.SERVICE)
    else if(receivers.contains(comp)) Some(AndroidConstants.CompType.RECEIVER)
    else if(providers.contains(comp)) Some(AndroidConstants.CompType.PROVIDER)
    else None
  }
  
	def setComponents(comps: ISet[(JawaClass, ComponentType.Value)]) = this.synchronized{
    comps.foreach{
      case (ac, typ) => 
        typ match {
          case ComponentType.ACTIVITY =>
            this.addActivity(ac)
          case ComponentType.SERVICE =>
            this.addService(ac)
          case ComponentType.RECEIVER =>
            this.addReceiver(ac)
          case ComponentType.PROVIDER =>
            this.addProvider(ac)
        }
    }
  }
	
	def getComponents: ISet[JawaClass] = (this.activities ++ this.services ++ this.receivers ++ this.providers).toSet
	def getActivities: ISet[JawaClass] = this.activities.toSet
  def getServices: ISet[JawaClass] = this.services.toSet
  def getReceivers: ISet[JawaClass] = this.receivers.toSet
  def getProviders: ISet[JawaClass] = this.providers.toSet
  
	def addDynamicRegisteredReceiver(receiver: JawaClass) = 
    this.synchronized{
      this.dynamicRegisteredReceivers += receiver
      this.receivers += receiver
    }

	def getDynamicRegisteredReceivers = this.dynamicRegisteredReceivers
	
	def setIntentFilterDB(i: IntentFilterDataBase) = this.synchronized{this.intentFdb.reset.merge(i)}
	
	def updateIntentFilterDB(i: IntentFilterDataBase) = this.synchronized{this.intentFdb.merge(i)}
	
	def getIntentFilterDB ={
	  if(this.intentFdb == null) throw new RuntimeException("intent-filter database does not exist.")
	  this.intentFdb
	}
	
	/**
	 * hold application information (current only used for android app)
	 */
	
	private var appInfoOpt: Option[AppInfoCollector] = None
	
	/**
	 * set application info
	 */
	  
	def setAppInfo(info: AppInfoCollector) = this.appInfoOpt = Some(info)
	
	/**
	 * get application info
	 */
	  
	def getAppInfo: AppInfoCollector = 
	  this.appInfoOpt match{
	    case Some(info) => info
	    case None => throw new RuntimeException("AppInfo does not exist.")
  	}
  
  def getAppName: String = FileUtil.toFile(nameUri).getName
  
  private val idfgResults: MMap[JawaClass, InterProceduralDataFlowGraph] = mmapEmpty
  
  def addIDFG(key: JawaClass, idfg: InterProceduralDataFlowGraph) = this.synchronized(this.idfgResults += (key -> idfg))
  def hasIDFG(key: JawaClass): Boolean = this.synchronized(this.idfgResults.contains(key))
  def getIDFG(key: JawaClass): Option[InterProceduralDataFlowGraph] = this.synchronized(this.idfgResults.get(key))
  def getIDFGs = this.idfgResults.toMap
  
  private val iddaResults: MMap[JawaClass, InterproceduralDataDependenceInfo] = mmapEmpty
  
  def addIDDG(key: JawaClass, iddi: InterproceduralDataDependenceInfo) = this.synchronized(this.iddaResults += (key -> iddi))
  def hasIDDG(key: JawaClass): Boolean = this.iddaResults.contains(key)
  def getIDDG(key: JawaClass): Option[InterproceduralDataDependenceInfo] = this.synchronized(this.iddaResults.get(key))
  def getIDDGs = this.iddaResults.toMap
  
  private var taintResult: Option[Any] = None
  
  def addTaintAnalysisResult[N <: InterProceduralNode, E <: AlirEdge[N]](tar: TaintAnalysisResult[N, E]) = this.synchronized(this.taintResult = Some(tar))
  def hasTaintAnalysisResult: Boolean = taintResult.isDefined
  def getTaintAnalysisResult[N <: InterProceduralNode, E <: AlirEdge[N]] = this.taintResult.map{v => v.asInstanceOf[TaintAnalysisResult[N, E]]}
  
  def reset = {
    this.activities.clear()
    this.services.clear()
    this.receivers.clear()
    this.providers.clear()
    this.dynamicRegisteredReceivers.clear()
    this.intentFdb.reset
	  this.appInfoOpt = None
	  this.idfgResults.clear
	  this.iddaResults.clear
	  this.taintResult = None
  }
}