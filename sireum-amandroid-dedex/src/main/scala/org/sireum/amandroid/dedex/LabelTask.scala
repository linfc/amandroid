/*
Copyright (c) 2015-2016 Fengguo Wei, University of South Florida.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.dedex

import org.sireum.util._

/**
 * @author fgwei
 */
case class LabelTask(label: String, instrParser: DexInstructionToPilarParser, priority: Int) extends PilarDedexerTask {
  def base = 0
  def offset = 0
  
  def doTask(isSecondPass: Boolean) = {
  }

  def renderTask(position: Long): IList[String] = {
    val code: StringBuilder = new StringBuilder
    code.append("#%s.  ".format(label))
    List(code.toString())
  }

  override def toString: String = label

  override def getPriority: Int = MIN_PRIORITY + 100 + priority      // always first
}