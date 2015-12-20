/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University. Qidan He.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.security.apiMisuse

import org.sireum.util.FileUtil
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.sireum.amandroid.security.AmandroidSocket
import org.sireum.amandroid.AndroidConstants
import org.sireum.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysis
import org.sireum.jawa.ClassLoadManager
import org.sireum.jawa.alir.controlFlowGraph.ICFGNode
import org.sireum.jawa.alir.controlFlowGraph.ICFGCallNode
import org.sireum.util.MSet
import org.sireum.util.MMap
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.sireum.pilar.ast.NameExp
import org.sireum.pilar.ast.TupleExp
import org.sireum.pilar.ast.CallJump
import org.sireum.jawa.JawaMethod
import org.sireum.pilar.ast.JumpLocation
import org.sireum.util.MList
<<<<<<< HEAD
<<<<<<< HEAD
=======
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.VarSlot
import org.sireum.jawa.alir.interProcedural.InterProceduralDataFlowGraph
>>>>>>> CommunicationLeakage
import org.sireum.jawa.MessageCenter._
=======
>>>>>>> upstream/master
import org.sireum.util._
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.sireum.jawa.alir.controlFlowGraph._
import org.sireum.pilar.ast._
<<<<<<< HEAD
import org.sireum.jawa.Center
<<<<<<< HEAD
=======
import org.sireum.jawa.alir.interProcedural.InterProceduralMonotoneDataFlowAnalysisResult
import org.sireum.jawa.alir.pta.reachingFactsAnalysis.VarSlot
import org.sireum.jawa.JawaProcedure
>>>>>>> CommunicationLeakage
=======
>>>>>>> upstream/master
import org.sireum.amandroid.util.AndroidLibraryAPISummary
import org.sireum.amandroid.security.AmandroidSocketListener
import org.sireum.jawa.util.IgnoreException
import org.sireum.jawa.alir.reachability.ReachabilityAnalysis
import org.sireum.jawa.alir.dataFlowAnalysis.InterProceduralDataFlowGraph
import org.sireum.jawa.alir.pta.VarSlot
import org.sireum.jawa.alir.pta.PTAResult
import org.sireum.jawa.Global
/*
 * @author <a href="mailto:i@flanker017.me">Qidan He</a>
 */
object LogSensitiveInfo {
  // private final val API_SIG = "Lorg/apache/http/conn/ssl/SSLSocketFactory;.setHostnameVerifier:(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V"
  // private final val API_SIG = "Landroid/content/BroadcastReceiver;.abortBroadcast:()V"
  private final val API_SIG = "Landroid/util/Log;.i:(Ljava/lang/String;Ljava/lang/String;)I"
  private final val VUL_PARAM = "@@org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER"
  
  def apply(global: Global, idfg : InterProceduralDataFlowGraph) : Unit
    = build(global, idfg)
    
  def build(global: Global, idfg : InterProceduralDataFlowGraph) : Unit = {
    val icfg = idfg.icfg
    val ptaresult = idfg.ptaresult
    val nodeMap : MMap[String, MSet[ICFGCallNode]] = mmapEmpty
    val callmap = icfg.getCallGraph.getCallMap
    icfg.nodes.foreach{
      node =>
        val result = getParticularAPINode(global, node)
        result.foreach{
          r =>
            nodeMap.getOrElseUpdate(r._1, msetEmpty) += r._2
        }
    }
    val rule1Res = VerifierCheck(global, nodeMap, ptaresult)
    rule1Res.foreach{
      case (n, b) =>
        if(!b){
          println(n.context + " using wrong ssl hostname configuration!")
        }
    }
  }
  
  /**
   * detect constant propagation on ALLOW_ALLHOSTNAME_VERIFIER
   * which is a common api miuse in many android apps.
   */
  def VerifierCheck(global: Global, nodeMap : MMap[String, MSet[ICFGCallNode]], ptaresult : PTAResult): Map[ICFGCallNode, Boolean] = {
    var result : Map[ICFGCallNode, Boolean] = Map()
    val nodes : MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(sig.equals(API_SIG))
          nodes ++= ns
    }
    nodes.foreach{
      node =>
        println("ZWZW - verify checker on " + node.toString())
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
        /*val argValue = rfaFacts.filter(p=>argSlot == p.s).map(_.v)
        argValue.foreach{
          ins =>
            val defsites = ins.getDefSite
            val loc = Center.getMethodWithoutFailing(defsites.getMethodSig).getMethodBody.location(defsites.getCurrentLocUri)
            //The found definition loc should be an assignment action
            var bar:ActionLocation = loc.asInstanceOf[ActionLocation]
            var as:AssignAction = bar.action.asInstanceOf[AssignAction]
            //retrive right side value
            var nameExp:NameExp = as.rhs.asInstanceOf[NameExp]
            if(nameExp.name.name.equals(VUL_PARAM))
            {
              result += (node -> false)
            }
        }*/
    }
    result
  }
  
  def getParticularAPINode(global: Global, node : ICFGNode): Set[(String, ICFGCallNode)] = {
    val result : MSet[(String, ICFGCallNode)] = msetEmpty
    node match{
      case invNode : ICFGCallNode =>
        println("Calling getINTERESTINGAPI on node - " + node.toString())
        val calleeSet = invNode.getCalleeSet
        println("ZWZW - callee set for current invNode is - " + calleeSet.toString)
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
            println("ZWZW - callee's signature - " + calleep.getSignature)

//            if(calleep.getSignature == Center.UNKNOWN_PROCEDURE_SIG){
//              val calleeSignature = cj.getValueAnnotation("signature") match {
//                case Some(s) => s match {
//                  case ne : NameExp => ne.name.name
//                  case _ => ""
//                }
//                case None => throw new RuntimeException("cannot found annotation 'signature' from: " + cj)
//              }
//              callees ++= Center.getMethodDeclarations(calleeSignature)
//            } else {
              callees += calleep
//            }
            callees.foreach{
              callee =>
                println("=======")
                println("Got an callee - " + callee.getSignature)
                println("=======")

                if(callee.getSignature.equals(API_SIG)){
                  println("=======")
                  println("Got an interesting api call - " + API_SIG)
                  println("=======")
                  result += ((callee.getSignature.signature, invNode))
                }
            }
        }
      case _ =>
    }
    result.toSet
  }
}