/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.security.apiMisuse

import org.sireum.util._
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.sireum.jawa.alir.controlFlowGraph._
import org.sireum.pilar.ast._
<<<<<<< HEAD
import org.sireum.jawa.Center
<<<<<<< HEAD
=======
>>>>>>> upstream/master
import org.sireum.jawa.JawaMethod
import org.sireum.jawa.alir.pta.PTAConcreteStringInstance
import org.sireum.jawa.alir.dataFlowAnalysis.InterProceduralDataFlowGraph
import org.sireum.jawa.alir.pta.PTAResult
import org.sireum.jawa.alir.pta.VarSlot
<<<<<<< HEAD
=======
import org.sireum.jawa.alir.interProcedural.InterProceduralMonotoneDataFlowAnalysisResult
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.VarSlot
import org.sireum.jawa.JawaProcedure
import org.sireum.jawa.alir.pta.PTAConcreteStringInstance
>>>>>>> CommunicationLeakage
=======
import org.sireum.jawa.Global
>>>>>>> upstream/master

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object CryptographicMisuse {
  
  def apply(global: Global, idfg : InterProceduralDataFlowGraph) : Unit
  	= build(global, idfg)
  	
  def build(global: Global, idfg : InterProceduralDataFlowGraph) : Unit = {
    val icfg = idfg.icfg
    val ptaresult = idfg.ptaresult
    val nodeMap : MMap[String, MSet[ICFGCallNode]] = mmapEmpty
    icfg.nodes.foreach{
      node =>
        val result = getCryptoNode(global, node)
        result.foreach{
          r =>
            nodeMap.getOrElseUpdate(r._1, msetEmpty) += r._2
        }
    }
    val rule1Res = ECBCheck(global, nodeMap, ptaresult)
    rule1Res.foreach{
      case (n, b) =>
        if(!b){
          println(n.context + " using ECB mode!")
        }
    }
  }
  
  /**
   * Rule 1 forbids the use of ECB mode because ECB mode is deterministic and not stateful, 
   * thus cannot be IND-CPA secure.
   */
  def ECBCheck(global: Global, nodeMap : MMap[String, MSet[ICFGCallNode]], ptaresult : PTAResult) : Map[ICFGCallNode, Boolean] = {
    var result : Map[ICFGCallNode, Boolean] = Map()
    val nodes : MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
      	if(CryptographicConstants.getCipherGetinstanceAPIs.contains(sig))
      	  nodes ++= ns
    }
    nodes.foreach{
      node =>
        result += (node -> true)
<<<<<<< HEAD
        val loc = Center.getMethodWithoutFailing(node.getOwner).getMethodBody.location(node.getLocIndex)
=======
        val loc = global.getMethod(node.getOwner).get.getBody.location(node.getLocIndex)
>>>>>>> upstream/master
        val argNames : MList[String] = mlistEmpty
        loc match{
          case jumploc : JumpLocation =>
            jumploc.jump match {
              case t : CallJump if t.jump.isEmpty =>
                t.callExp.arg match {
				          case te : TupleExp =>
				            val exps = te.exps
				            for(i <- 0 to (exps.size-1)) {
				              val varName = exps(i) match{
				                case ne : NameExp => ne.name.name
				                case a => a.toString()
				              }
				              argNames += varName
		                }
				          case _ =>
				        }
              case _ =>
            }
          case _ =>
        }
        require(argNames.isDefinedAt(0))
        val argSlot = VarSlot(argNames(0), false, true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)
        argValue.foreach{
          ins =>
            if(ins.isInstanceOf[PTAConcreteStringInstance]){
              if(CryptographicConstants.getECBSchemes.contains(ins.asInstanceOf[PTAConcreteStringInstance].string))
                result += (node -> false)
            }
        }
    }
    result
  }
  
  def getCryptoNode(global: Global, node : ICFGNode) : Set[(String, ICFGCallNode)] = {
    val result : MSet[(String, ICFGCallNode)] = msetEmpty
    node match{
      case invNode : ICFGCallNode =>
        val calleeSet = invNode.getCalleeSet
		    calleeSet.foreach{
		      callee =>
		        val calleep = callee.callee
<<<<<<< HEAD
<<<<<<< HEAD
		        val callees : MSet[JawaMethod] = msetEmpty
				    val caller = Center.getMethodWithoutFailing(invNode.getOwner)
				    val jumpLoc = caller.getMethodBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation]
=======
		        val callees : MSet[JawaProcedure] = msetEmpty
				    val caller = Center.getProcedureWithoutFailing(invNode.getOwner)
				    val jumpLoc = caller.getProcedureBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation]
>>>>>>> CommunicationLeakage
=======
		        val callees : MSet[JawaMethod] = msetEmpty
				    val caller = global.getMethod(invNode.getOwner).get
				    val jumpLoc = caller.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation]
>>>>>>> upstream/master
				    val cj = jumpLoc.jump.asInstanceOf[CallJump]
//				    if(calleep.getSignature == Center.UNKNOWN_PROCEDURE_SIG){
//				      val calleeSignature = cj.getValueAnnotation("signature") match {
//				        case Some(s) => s match {
//				          case ne : NameExp => ne.name.name
//				          case _ => ""
//				        }
//				        case None => throw new RuntimeException("cannot found annotation 'signature' from: " + cj)
//				      }
//				      // source and sink APIs can only come from given app's parents.
//				      callees ++= Center.getMethodDeclarations(calleeSignature)
//				    } else {
				      callees += calleep
//				    }
		        callees.foreach{
		          callee =>
						    if(CryptographicConstants.getCryptoAPIs.contains(callee.getSignature.signature)){
						      result += ((callee.getSignature.signature, invNode))
						    }
		        }
		    }
      case _ =>
    }
    result.toSet
  }
}