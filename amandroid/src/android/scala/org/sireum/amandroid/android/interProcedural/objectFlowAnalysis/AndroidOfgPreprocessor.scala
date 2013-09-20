package org.sireum.amandroid.android.interProcedural.objectFlowAnalysis

import org.sireum.pilar.symbol.ProcedureSymbolTable
import org.sireum.alir.ControlFlowGraph
import org.sireum.alir.ReachingDefinitionAnalysis
import org.sireum.amandroid.interProcedural.objectFlowAnalysis.ObjectFlowGraphPreprocessor
import org.sireum.amandroid.interProcedural.objectFlowAnalysis.OfaNode
import org.sireum.amandroid.interProcedural.objectFlowAnalysis.ObjectFlowGraph
import org.sireum.amandroid.PointsCollector
import org.sireum.amandroid.interProcedural.Context
import org.sireum.util._
import org.sireum.amandroid.Point

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */
object AndroidOfgPreprocessor extends ObjectFlowGraphPreprocessor[OfaNode, AndroidValueSet] {  
  
  def apply(pst : ProcedureSymbolTable,
            cfg : ControlFlowGraph[String],
            rda : ReachingDefinitionAnalysis.Result) : AndroidObjectFlowGraph[OfaNode, AndroidValueSet]
            = build(pst, cfg, rda)
                    
  def build(pst : ProcedureSymbolTable,
            cfg : ControlFlowGraph[String],
            rda : ReachingDefinitionAnalysis.Result) : AndroidObjectFlowGraph[OfaNode, AndroidValueSet] = {
    val result = new AndroidObjectFlowGraph[OfaNode, AndroidValueSet]({() => new AndroidValueSet})
    doPreOfg(pst, cfg, rda, result)
    result
  }
  
  override def doPreOfg(pst : ProcedureSymbolTable, 
            cfg : ControlFlowGraph[String], 
            rda : ReachingDefinitionAnalysis.Result, 
            ofg : ObjectFlowGraph[OfaNode, AndroidValueSet]) = {
//    val points = new PointsCollector().points(pst)
    val points = mlistEmpty[Point]
    val context = new Context(ofg.K_CONTEXT)
    ofg.points ++= points
    ofg.constructGraph(pst.procedureUri, points, context.copy, cfg, rda)
  }
}