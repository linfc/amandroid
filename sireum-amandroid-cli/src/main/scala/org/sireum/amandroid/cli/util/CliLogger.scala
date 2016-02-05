/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.cli.util

import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.text.SimpleDateFormat
import java.util.Date

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */ 
object CliLogger {
  
  def timeStamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date)
  
  def outPrint(s : String) {
    scala.Console.out.print(s)
    scala.Console.out.flush
  }

  def outPrintln(s : String) {
    scala.Console.out.println(s)
    scala.Console.out.flush
  }

  def outPrintln {
    scala.Console.out.println
    scala.Console.out.flush
  }

  def errPrintln(s : String) {
    scala.Console.err.println(s)
    scala.Console.err.flush
  }

  def errPrintln {
    scala.Console.err.println
    scala.Console.err.flush
  }
  
  def logError(dir : File, text : String, e : Throwable) {
    outPrintln
    errPrintln(text + e.getMessage)
    val f = new File(dir, ".errorlog")
    f.getParentFile.mkdirs
    val fw = new FileWriter(f)
    try {
      val pw = new PrintWriter(fw)
      pw.println("An error occured on " + timeStamp)
      e.printStackTrace(pw)
      fw.close
      outPrintln("Written: " + f.getAbsolutePath)
    } catch {
      case e : Throwable =>
        errPrintln("Error: " + e.getMessage)
    }
  }
}