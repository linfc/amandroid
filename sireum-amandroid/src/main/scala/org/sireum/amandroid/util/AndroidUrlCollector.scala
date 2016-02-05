package org.sireum.amandroid.util

import org.sireum.util._
import org.sireum.amandroid.appInfo.AppInfoCollector
import org.sireum.amandroid.parser.ResourceFileParser
import org.sireum.jawa.util.URLInString
import org.sireum.jawa.Global

object AndroidUrlCollector {
  def collectUrls(global: Global, file : FileResourceUri, outUri : FileResourceUri) : ISet[String] = {
    val man = AppInfoCollector.analyzeManifest(global.reporter, outUri + "AndroidManifest.xml")
    val afp = AppInfoCollector.analyzeARSC(global.reporter, file)    
    val strs = msetEmpty[String]
    val rfp = new ResourceFileParser
    rfp.parseResourceFile(file)
    strs ++= rfp.getAllStrings
    strs ++= afp.getGlobalStringPool.map(_._2)
    val sources = global.getApplicationClassCodes
    val code_urls : Set[String] =
      if(!sources.isEmpty){
        sources.map{
          case (name, source) =>
            URLInString.extract(source.code)
        }.reduce(iunion[String])
      } else isetEmpty[String]
    val res_urls : Set[String] =
      if(!strs.isEmpty){
        strs.map{
          str =>
            URLInString.extract(str)
        }.reduce(iunion[String])
      } else isetEmpty[String]   
    code_urls ++ res_urls
  }
}