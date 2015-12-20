/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.security.password

import org.sireum.amandroid.parser.LayoutControl
import org.sireum.util._
import org.sireum.jawa.JawaMethod
<<<<<<< HEAD
import org.sireum.jawa.MessageCenter._
=======
>>>>>>> upstream/master
import org.sireum.jawa.alir.controlFlowGraph._
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.sireum.pilar.ast.JumpLocation
import org.sireum.amandroid.AndroidConstants
import org.sireum.jawa.alir.util.ExplicitValueFinder
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.ReachingFactsAnalysisHelper
import org.sireum.pilar.ast._
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
<<<<<<< HEAD
import org.sireum.jawa.alir.controlFlowGraph.ICFGInvokeNode
import org.sireum.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.sireum.jawa.alir.pta.VarSlot
import org.sireum.jawa.alir.pta.PTAResult
<<<<<<< HEAD
=======
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.VarSlot
import org.sireum.jawa.alir.controlFlowGraph.CGInvokeNode
import org.sireum.jawa.Center
import org.sireum.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
>>>>>>> CommunicationLeakage
=======
import org.sireum.jawa.Global
import org.sireum.amandroid.Apk
>>>>>>> upstream/master

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
<<<<<<< HEAD
class PasswordSourceAndSinkManager(appPackageName : String, 
    												layoutControls : Map[Int, LayoutControl], 
    												callbackMethods : ISet[JawaMethod], 
    												sasFilePath : String) extends AndroidSourceAndSinkManager(appPackageName, layoutControls, callbackMethods, sasFilePath){
=======
class PasswordSourceAndSinkManager(
    global: Global,
    apk: Apk, 
    layoutControls : Map[Int, LayoutControl], 
    callbackMethods : ISet[JawaMethod], 
    sasFilePath : String) extends AndroidSourceAndSinkManager(global, apk, layoutControls, callbackMethods, sasFilePath){
>>>>>>> upstream/master
  private final val TITLE = "PasswordSourceAndSinkManager"
    
  def isCallbackSource(proc : JawaMethod) : Boolean = {
    false
  }
  
<<<<<<< HEAD
	def isUISource(calleeMethod : JawaMethod, callerMethod : JawaMethod, callerLoc : JumpLocation) : Boolean = {
	  if(calleeMethod.getSignature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeMethod.getSignature == AndroidConstants.VIEW_FINDVIEWBYID){
	    val nums = ExplicitValueFinder.findExplicitIntValueForArgs(callerMethod, callerLoc, 1)
	    nums.foreach{
	      num =>
	        this.layoutControls.get(num) match{
	          case Some(control) =>
	            return control.isSensitive
	          case None =>
	            err_msg_normal(TITLE, "Layout control with ID " + num + " not found.")
	        }
	    }
	  }
	  false
	}
	
	def isIccSink(invNode : ICFGInvokeNode, ptaresult : PTAResult) : Boolean = {
	  var sinkflag = false
=======
  def isUISource(calleeMethod : JawaMethod, callerMethod : JawaMethod, callerLoc : JumpLocation) : Boolean = {
    if(calleeMethod.getSignature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeMethod.getSignature == AndroidConstants.VIEW_FINDVIEWBYID){
      val nums = ExplicitValueFinder.findExplicitIntValueForArgs(callerMethod, callerLoc, 1)
      nums.foreach{
        num =>
          this.layoutControls.get(num) match{
            case Some(control) =>
              return control.isSensitive
            case None =>
              global.reporter.error(TITLE, "Layout control with ID " + num + " not found.")
          }
      }
    }
    false
  }

  def isIccSink(invNode : ICFGInvokeNode, ptaresult : PTAResult) : Boolean = {
    var sinkflag = false
>>>>>>> upstream/master
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkflag = true
<<<<<<< HEAD
          val args = Center.getMethodWithoutFailing(invNode.getOwner).getMethodBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match{
              case te : TupleExp =>
                te.exps.map{
			            exp =>
			              exp match{
					            case ne : NameExp => ne.name.name
					            case _ => exp.toString()
					          }
			          }.toList
              case a => throw new RuntimeException("wrong exp type: " + a)
            }
          val intentSlot = VarSlot(args(1))
          val intentValues = ptaresult.pointsToSet(intentSlot, invNode.getContext)
          val intentContents = IntentHelper.getIntentContents(ptaresult, intentValues, invNode.getContext)
          val compType = AndroidConstants.getIccCallType(callee.callee.getSubSignature)
          val comMap = IntentHelper.mappingIntents(intentContents, compType)
=======
          val args = global.getMethod(invNode.getOwner).get.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match{
            case te : TupleExp =>
              te.exps.map{
                exp =>
                  exp match{
                    case ne : NameExp => ne.name.name
                    case _ => exp.toString()
                  }
              }.toList
            case a => throw new RuntimeException("wrong exp type: " + a)
          }
          val intentSlot = VarSlot(args(1), false, true)
          val intentValues = ptaresult.pointsToSet(intentSlot, invNode.getContext)
          val intentContents = IntentHelper.getIntentContents(ptaresult, intentValues, invNode.getContext)
          val compType = AndroidConstants.getIccCallType(callee.callee.getSubSignature)
          val comMap = IntentHelper.mappingIntents(global, apk, intentContents, compType)
>>>>>>> upstream/master
          comMap.foreach{
            case (_, coms) =>
              if(coms.isEmpty) sinkflag = true
              coms.foreach{
                case (com, typ) =>
                  typ match {
                    case IntentHelper.IntentType.EXPLICIT => if(com.isUnknown) sinkflag = true
//                    case IntentHelper.IntentType.EXPLICIT => sinkflag = true
                    case IntentHelper.IntentType.IMPLICIT => sinkflag = true
                  }
              }
          }
        }
    }
    sinkflag
  }

  def isIccSource(entNode : ICFGNode, iddgEntNode : ICFGNode) : Boolean = {
    false
  }

}