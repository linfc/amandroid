/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.parser

import org.sireum.util.FileResourceUri
import brut.androlib.res.util.ExtFile
import brut.androlib.res.decoder.ARSCDecoder
import brut.androlib.res.decoder.ARSCDecoder.ARSCData
import brut.androlib.res.data.ResID
import brut.androlib.res.data.ResResSpec
import brut.androlib.res.data.ResPackage
import java.util.regex.Pattern
import org.sireum.util._
import java.util.zip.ZipFile

class ARSCFileParser_apktool {
  final private val TITLE = "ARSCFileParser_apktool"
  private var data : ARSCData = null
  
  def parse(apkUri : FileResourceUri) : Unit = {
    val apkFile = FileUtil.toFilePath(apkUri)
    val zf = new ZipFile(apkFile)
    try{
      val ze = zf.getEntry("resources.arsc")
      if(ze != null){
        val in = zf.getInputStream(ze)
        this.data = ARSCDecoder.decode(in, false, false)
      } else {}//err_msg_normal(TITLE, "Cannot find resources.arsc file.")
    } finally {
      zf.close()
    }
  }
  
  def findResource(resourceId : Int) : ResResSpec = {
    var result : ResResSpec = null
    val id = new ResID(resourceId)
    if(this.data != null){
      this.data.getPackages.foreach{
        pkg =>
          if(pkg.hasResSpec(id)){
            result = pkg.getResSpec(id)
          }
      }
    }
    result
  }
  
  def getPackages : Set[ResPackage] = {
    if(this.data != null){
      data.getPackages.toSet
    } else Set()
  }
  
  def getGlobalStringPool : Map[Int, String] = {
    val matches : MMap[Int, String] = mmapEmpty
    getPackages.map{
      pkg =>
        val str = pkg.getResTable.toString()
        val strs = str.substring(1, str.length() - 1).split(", ")
        val p = Pattern.compile("(.+)\\sstring\\/(.+)") 
        var matches : Map[Int, String] = Map()
        strs foreach{
          str =>
          
            val m = p.matcher(str)
            if(m.find()){
              matches += (Integer.parseInt(m.group(1).substring(2), 16) -> m.group(2))
            }
        }
    }
    matches.toMap
  }
}