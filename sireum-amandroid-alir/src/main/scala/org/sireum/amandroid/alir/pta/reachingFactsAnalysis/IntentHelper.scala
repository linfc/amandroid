/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.alir.pta.reachingFactsAnalysis

import org.sireum.util._
<<<<<<< HEAD:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/IntentHelper.scala
import org.sireum.jawa.alir.pta.Instance
=======
import org.sireum.jawa.alir.Instance
>>>>>>> CommunicationLeakage:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/IntentHelper.scala
import org.sireum.jawa.alir.pta.reachingFactsAnalysis._
import org.sireum.amandroid.AndroidConstants
import org.sireum.alir.Slot
<<<<<<< HEAD
import org.sireum.jawa.util.StringFormConverter
=======
>>>>>>> upstream/master
import org.sireum.jawa.JawaClass
import org.sireum.amandroid.parser.UriData
import java.net.URI
import org.sireum.jawa.alir.Context
<<<<<<< HEAD
import org.sireum.jawa.Center
import org.sireum.jawa.MessageCenter._
=======
>>>>>>> upstream/master
import java.net.URLEncoder
import org.sireum.jawa.alir.pta.PTAConcreteStringInstance
<<<<<<< HEAD:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/IntentHelper.scala
import org.sireum.jawa.alir.pta.PTAResult
import org.sireum.jawa.alir.pta.FieldSlot
<<<<<<< HEAD
=======
>>>>>>> CommunicationLeakage:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/IntentHelper.scala
=======
import org.sireum.jawa.JavaKnowledge
import org.sireum.amandroid.Apk
import org.sireum.jawa.Global
import org.sireum.jawa.JawaType
>>>>>>> upstream/master

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object IntentHelper {
  final val TITLE = "IntentHelper"
  val DEBUG = false
  
  object IntentType extends Enumeration {
    val EXPLICIT, IMPLICIT = Value
  }
  
<<<<<<< HEAD
  final case class IntentContent(componentNames: ISet[String], 
      													 actions: ISet[String], 
      													 categories: ISet[String], 
      													 datas: ISet[UriData], 
      													 types: ISet[String], 
      													 preciseExplicit: Boolean,
      													 preciseImplicit: Boolean,
      													 senderContext: Context)
  
	def getIntentContents(s: PTAResult, intentValues: ISet[Instance], currentContext: Context): ISet[IntentContent] = {
	  var result = isetEmpty[IntentContent]
	  intentValues.foreach{
=======
  final case class IntentContent(
      componentNames: ISet[String], 
      actions: ISet[String], 
      categories: ISet[String], 
      datas: ISet[UriData], 
      types: ISet[String], 
      preciseExplicit: Boolean,
      preciseImplicit: Boolean)
  
  def getIntentContents(s: PTAResult, intentValues: ISet[Instance], currentContext: Context): ISet[IntentContent] = {
    var result = isetEmpty[IntentContent]
    intentValues.foreach {
>>>>>>> upstream/master
      intentIns =>
        var preciseExplicit = true
        var preciseImplicit = true
        var componentNames = isetEmpty[String]
        val iFieldSlot = FieldSlot(intentIns, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_COMPONENT))
        s.pointsToSet(iFieldSlot, currentContext).foreach{
          compIns =>
            val cFieldSlot = FieldSlot(compIns, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.COMPONENTNAME_CLASS))
            s.pointsToSet(cFieldSlot, currentContext).foreach{
              ins =>
                if(ins.isInstanceOf[PTAConcreteStringInstance]){
                  componentNames += ins.asInstanceOf[PTAConcreteStringInstance].string
                }
                else preciseExplicit = false
            }
        }
        var actions: ISet[String] = isetEmpty[String]
        val acFieldSlot = FieldSlot(intentIns, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_ACTION))
        s.pointsToSet(acFieldSlot, currentContext).foreach{
          acIns =>
            if(acIns.isInstanceOf[PTAConcreteStringInstance])
              actions += acIns.asInstanceOf[PTAConcreteStringInstance].string
            else preciseImplicit = false
        }
        
        var categories = isetEmpty[String] // the code to get the valueSet of categories is to be added below
        val categoryFieldSlot = FieldSlot(intentIns, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_CATEGORIES))
        s.pointsToSet(categoryFieldSlot, currentContext).foreach{
          cateIns =>
            val hashSetFieldSlot = FieldSlot(cateIns, "items")
            s.pointsToSet(hashSetFieldSlot, currentContext).foreach{
              itemIns =>
                if(itemIns.isInstanceOf[PTAConcreteStringInstance])
                  categories += itemIns.asInstanceOf[PTAConcreteStringInstance].string
                else preciseImplicit = false
            }
        }
        
        var datas: ISet[UriData] = isetEmpty
        val dataFieldSlot = FieldSlot(intentIns, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_URI_DATA))
        s.pointsToSet(dataFieldSlot, currentContext).foreach{
          dataIns =>
            val uriStringFieldSlot = FieldSlot(dataIns, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.URI_STRING_URI_URI_STRING))
            s.pointsToSet(uriStringFieldSlot, currentContext).foreach{
              usIns =>
                if(usIns.isInstanceOf[PTAConcreteStringInstance]){
                  val uriString = usIns.asInstanceOf[PTAConcreteStringInstance].string
                  var uriData = new UriData
                  populateByUri(uriData, uriString)
                  datas +=uriData
                } else preciseImplicit = false
            }
        }
        
        var types:Set[String] = Set()
        val mtypFieldSlot = FieldSlot(intentIns, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_MTYPE))
        s.pointsToSet(mtypFieldSlot, currentContext).foreach{
          mtypIns =>
            if(mtypIns.isInstanceOf[PTAConcreteStringInstance])
              types += mtypIns.asInstanceOf[PTAConcreteStringInstance].string
            else preciseImplicit = false
        }
        val ic = IntentContent(componentNames, actions, categories, datas, types, 
             preciseExplicit, preciseImplicit)
        result += ic
    }
    result
  }

  def populateByUri(data: UriData, uriData: String) = {
    var scheme:String = null
    var host:String = null
    var port:String = null
    var path:String = null
    if(uriData != null){
<<<<<<< HEAD
      if(!uriData.startsWith("tel:") && !uriData.startsWith("file:") && uriData.contains("://") && uriData.indexOf("://") < uriData.length()){
=======
      if(!uriData.startsWith("tel:") && !uriData.startsWith("file:") && uriData.contains("://") && uriData.indexOf("://") < uriData.length()) {
>>>>>>> upstream/master
        var legalUriStr: String = uriData
        if(uriData.contains("=")){
          val (head, query) = uriData.splitAt(uriData.indexOf("=") + 1)
          legalUriStr = head + URLEncoder.encode(query, "UTF-8")
        }
        try{
          val uri = URI.create(legalUriStr)
          scheme = uri.getScheme()
          host = uri.getHost()
          port = if(uri.getPort() != -1) uri.getPort().toString else null
          path = if(uri.getPath() != "") uri.getPath() else null
          data.set(scheme, host, port, path, null, null)
        } catch {
<<<<<<< HEAD
          case e: IllegalArgumentException => err_msg_normal(TITLE, "Unexpected uri: " + legalUriStr)
=======
          case e: IllegalArgumentException => // err_msg_normal(TITLE, "Unexpected uri: " + legalUriStr)
>>>>>>> upstream/master
        }
      } else if(uriData.contains(":")){  // because e.g. app code can have intent.setdata("http:") instead of intent.setdata("http://xyz:200/pqr/abc")
        scheme = uriData.split(":")(0)
        if(scheme != null)
          data.setScheme(scheme)
      }
    }
  }
<<<<<<< HEAD
	
	def mappingIntents(intentContents: ISet[IntentContent], compType: AndroidConstants.CompType.Value): IMap[IntentContent, ISet[(JawaClass, IntentType.Value)]] = {
	  intentContents.map{
	    ic =>
	      val components: MSet[(JawaClass, IntentType.Value)] = msetEmpty
        if(!ic.preciseExplicit){
          compType match {
            case AndroidConstants.CompType.ACTIVITY =>
              components ++= AppCenter.getActivities.map((_, IntentType.EXPLICIT))
            case AndroidConstants.CompType.SERVICE =>
              components ++= AppCenter.getServices.map((_, IntentType.EXPLICIT))
            case AndroidConstants.CompType.RECEIVER =>
              components ++= AppCenter.getReceivers.map((_, IntentType.EXPLICIT))
            case AndroidConstants.CompType.PROVIDER =>
              components ++= AppCenter.getProviders.map((_, IntentType.EXPLICIT))
=======

  def mappingIntents(global: Global, apk: Apk, intentContents: ISet[IntentContent], compType: AndroidConstants.CompType.Value): IMap[IntentContent, ISet[(JawaClass, IntentType.Value)]] = {
    intentContents.map{
      ic =>
        val components: MSet[(JawaClass, IntentType.Value)] = msetEmpty
        if(!ic.preciseExplicit){
          compType match {
            case AndroidConstants.CompType.ACTIVITY =>
              components ++= apk.getActivities.map((_, IntentType.EXPLICIT))
            case AndroidConstants.CompType.SERVICE =>
              components ++= apk.getServices.map((_, IntentType.EXPLICIT))
            case AndroidConstants.CompType.RECEIVER =>
              components ++= apk.getReceivers.map((_, IntentType.EXPLICIT))
            case AndroidConstants.CompType.PROVIDER =>
              components ++= apk.getProviders.map((_, IntentType.EXPLICIT))
>>>>>>> upstream/master
          }
        } else if(!ic.preciseImplicit) {
          compType match {
            case AndroidConstants.CompType.ACTIVITY =>
<<<<<<< HEAD
              components ++= AppCenter.getActivities.map((_, IntentType.IMPLICIT))
            case AndroidConstants.CompType.SERVICE =>
              components ++= AppCenter.getServices.map((_, IntentType.IMPLICIT))
            case AndroidConstants.CompType.RECEIVER =>
              components ++= AppCenter.getReceivers.map((_, IntentType.IMPLICIT))
            case AndroidConstants.CompType.PROVIDER =>
              components ++= AppCenter.getProviders.map((_, IntentType.IMPLICIT))
          }
        }
	      ic.componentNames.foreach{
	        targetRecName =>
		        val targetRec = Center.resolveClass(targetRecName, Center.ResolveLevel.HIERARCHY)
            if(DEBUG)
            	msg_detail(TITLE, "explicit target component: " + targetRec)
            components += ((targetRec, IntentType.EXPLICIT))
	      }
	      components ++= findComponents(ic.actions, ic.categories, ic.datas, ic.types).map((_, IntentType.IMPLICIT))
	      (ic, components.toSet)
	  }.toMap
	}
	
	private def findComponents(actions: Set[String], categories: Set[String], datas: Set[UriData], mTypes:Set[String]): ISet[JawaClass] = {
=======
              components ++= apk.getActivities.filter(ep => !apk.getIntentFilterDB.getIntentFilters(ep).isEmpty).map((_, IntentType.IMPLICIT))
            case AndroidConstants.CompType.SERVICE =>
              components ++= apk.getServices.filter(ep => !apk.getIntentFilterDB.getIntentFilters(ep).isEmpty).map((_, IntentType.IMPLICIT))
            case AndroidConstants.CompType.RECEIVER =>
              components ++= apk.getReceivers.filter(ep => !apk.getIntentFilterDB.getIntentFilters(ep).isEmpty).map((_, IntentType.IMPLICIT))
            case AndroidConstants.CompType.PROVIDER =>
              components ++= apk.getProviders.filter(ep => !apk.getIntentFilterDB.getIntentFilters(ep).isEmpty).map((_, IntentType.IMPLICIT))
          }
        }
        ic.componentNames.foreach{
          targetRecName =>
            val targetRec = global.getClassOrResolve(new JawaType(targetRecName))
            components += ((targetRec, IntentType.EXPLICIT))
        }
        components ++= findComponents(apk, ic.actions, ic.categories, ic.datas, ic.types).map((_, IntentType.IMPLICIT))
        (ic, components.toSet)
    }.toMap
  }

  def findComponents(apk: Apk, actions: Set[String], categories: Set[String], datas: Set[UriData], mTypes:Set[String]): ISet[JawaClass] = {
>>>>>>> upstream/master
    var components: ISet[JawaClass] = isetEmpty
    if(actions.isEmpty){
      if(datas.isEmpty){
        if(mTypes.isEmpty) components ++= findComps(apk, null, categories, null, null) 
        else mTypes.foreach{components ++= findComps(apk, null, categories, null, _)}
      } else {
        datas.foreach{
          data =>
            if(mTypes.isEmpty) components ++= findComps(apk, null, categories, data, null) 
            else mTypes.foreach{components ++= findComps(apk, null, categories, data, _)}
        }
      }
    } else {  
      actions.foreach{
        action =>
          if(datas.isEmpty){
             if(mTypes.isEmpty) components ++= findComps(apk, action, categories, null, null) 
             else mTypes.foreach{components ++= findComps(apk, action, categories, null, _)}
          } else {
            datas.foreach{
              data =>
                if(mTypes.isEmpty) components ++= findComps(apk, action, categories, data, null) 
                else mTypes.foreach{components ++= findComps(apk, action, categories, data, _)} 
            }
          }
      }
    }
    components
  }
  
<<<<<<< HEAD
  private def findComps(action:String, categories: Set[String], data:UriData, mType:String): ISet[JawaClass] = {
    var components: ISet[JawaClass] = isetEmpty
    AppCenter.getComponents.foreach{
	    ep =>
	      val iFilters = AppCenter.getIntentFilterDB.getIntentFilters(ep)
	      if(!iFilters.isEmpty){
	        val matchedFilters = iFilters.filter(iFilter => iFilter.isMatchWith(action, categories, data, mType))
	        if(!matchedFilters.isEmpty)
	          components += ep
	      }
=======
  private def findComps(apk: Apk, action:String, categories: Set[String], data:UriData, mType:String): ISet[JawaClass] = {
    var components: ISet[JawaClass] = isetEmpty
    apk.getComponents.foreach {
      ep =>
        val iFilters = apk.getIntentFilterDB.getIntentFilters(ep)
        if(!iFilters.isEmpty){
          val matchedFilters = iFilters.filter(iFilter => iFilter.isMatchWith(action, categories, data, mType))
          if(!matchedFilters.isEmpty)
            components += ep
        }
>>>>>>> upstream/master
    }
    components
  }
}