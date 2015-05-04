/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.security.dataInjection

import org.sireum.amandroid.parser.LayoutControl
import org.sireum.util._
import org.sireum.jawa.JawaMethod
import org.sireum.jawa.MessageCenter._
import org.sireum.pilar.ast._
import org.sireum.amandroid.AndroidConstants
import org.sireum.jawa.alir.util.ExplicitValueFinder
import org.sireum.jawa.alir.controlFlowGraph.ICFGInvokeNode
import org.sireum.jawa.alir.controlFlowGraph.ICFGNode
import org.sireum.jawa.Center
import org.sireum.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.sireum.jawa.alir.pta.PTAResult

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class IntentInjectionSourceAndSinkManager(appPackageName : String, 
    												layoutControls : Map[Int, LayoutControl], 
    												callbackMethods : ISet[JawaMethod], 
    												sasFilePath : String) 
    												extends AndroidSourceAndSinkManager(appPackageName, layoutControls, callbackMethods, sasFilePath){
  
  override def isSource(calleeMethod : JawaMethod, callerMethod : JawaMethod, callerLoc : JumpLocation) : Boolean = {
	  false
	}
  
  override def isCallbackSource(proc : JawaMethod) : Boolean = {
    false
  }
  
	override def isUISource(calleeMethod : JawaMethod, callerMethod : JawaMethod, callerLoc : JumpLocation) : Boolean = {
//	  if(calleeMethod.getSignature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeMethod.getSignature == AndroidConstants.VIEW_FINDVIEWBYID){
//	    val nums = ExplicitValueFinder.findExplicitIntValueForArgs(callerMethod, callerLoc, 1)
//	    nums.foreach{
//	      num =>
//	        this.layoutControls.get(num) match{
//	          case Some(control) =>
//	            return control.isSensitive
//	          case None =>
//	            err_msg_normal("Layout control with ID " + num + " not found.")
//	        }
//	    }
//	  }
	  false
	}
	
	override def isIccSink(invNode : ICFGInvokeNode, ptaresult : PTAResult) : Boolean = {
	  var sinkflag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkflag = true
//          val rfafactMap = ReachingFactsAnalysisHelper.getFactMap(rfaFact)
//          val args = invNode.getOwner.getMethodBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match{
//              case te : TupleExp =>
//                te.exps.map{
//			            exp =>
//			              exp match{
//					            case ne : NameExp => ne.name.name
//					            case _ => exp.toString()
//					          }
//			          }.toList
//              case a => throw new RuntimeException("wrong exp type: " + a)
//            }
//          val intentSlot = VarSlot(args(1))
//          val intentValues = rfafactMap.getOrElse(intentSlot, isetEmpty)
//          val intentContents = IntentHelper.getIntentContents(rfafactMap, intentValues, invNode.getContext)
//          val comMap = IntentHelper.mappingIntents(intentContents)
//          comMap.foreach{
//            case (_, coms) =>
//              if(coms.isEmpty) sinkflag = true
//              coms.foreach{
//                case (com, typ) =>
//                  typ match {
//                    case IntentHelper.IntentType.EXPLICIT => if(com.isPhantom) sinkflag = true
////                    case IntentHelper.IntentType.EXPLICIT => sinkflag = true
//                    case IntentHelper.IntentType.IMPLICIT => sinkflag = true
//                  }
//              }
//          }
        }
    }
    sinkflag
	}
	
	override def isIccSource(entNode : ICFGNode, iddgEntNode : ICFGNode) : Boolean = {
	  entNode == iddgEntNode
	}
}