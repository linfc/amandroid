/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.security.oauth

import org.sireum.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.sireum.amandroid.parser.LayoutControl
import org.sireum.util._
import org.sireum.jawa.JawaMethod
import org.sireum.jawa.alir.controlFlowGraph.ICFGCallNode
import org.sireum.jawa.alir.controlFlowGraph.ICFGNode
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.sireum.pilar.ast.JumpLocation
import org.sireum.amandroid.AndroidConstants
import org.sireum.jawa.alir.util.ExplicitValueFinder
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.ReachingFactsAnalysisHelper
import org.sireum.pilar.ast._
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.sireum.jawa.alir.controlFlowGraph.ICFGInvokeNode
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.sireum.jawa.alir.pta.VarSlot
import org.sireum.jawa.alir.pta.PTAResult
import org.sireum.amandroid.Apk
import org.sireum.jawa.Global

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class OAuthSourceAndSinkManager(
    global: Global,
    apk: Apk, 
    layoutControls: Map[Int, LayoutControl], 
    callbackMethods: ISet[JawaMethod], 
    sasFilePath: String) extends AndroidSourceAndSinkManager(global, apk, layoutControls, callbackMethods, sasFilePath){
  
  private final val TITLE = "OAuthSourceAndSinkManager"
    
  override def isSource(calleeMethod: JawaMethod, callerMethod: JawaMethod, callerLoc: JumpLocation) = false
    
  override def isCallbackSource(proc: JawaMethod): Boolean = {
    false
  }
  
  override def isUISource(calleeMethod: JawaMethod, callerMethod: JawaMethod, callerLoc: JumpLocation): Boolean = {
    false
  }

  override def isSource(loc: LocationDecl, ptaresult: PTAResult): Boolean = {
    var flag = false
    val visitor = Visitor.build({
      case as: AssignAction =>
        as.rhs match {
          case le: LiteralExp =>
            if(le.typ.name.equals("STRING")){
              if(le.text.contains("content://call_log/calls"))
                flag = true
            }
            false
          case _ =>
            false
        }
    })
  
    visitor(loc)
    flag
  }

  def isIccSink(invNode: ICFGInvokeNode, ptaresult: PTAResult): Boolean = {
    var sinkflag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkflag = true
          val args = global.getMethod(invNode.getOwner).get.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match{
              case te: TupleExp =>
                te.exps.map{
                  exp =>
                    exp match{
                      case ne: NameExp => ne.name.name
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

	def isIccSource(entNode: ICFGNode, iddgEntNode: ICFGNode): Boolean = {
	  false
	}
	
}