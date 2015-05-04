/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.parser

import org.sireum.jawa.JawaClass
import org.sireum.jawa.Center
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class IntentFilterDataBase {
  /**
   * Map from record name to it's intent filter information
   */
  private val intentFmap: MMap[String, Set[IntentFilter]] = mmapEmpty
  def updateIntentFmap(intentFilter: IntentFilter) = {
    this.intentFmap += (intentFilter.getHolder -> (this.intentFmap.getOrElse(intentFilter.getHolder, Set()) + intentFilter))
  }
  def merge(intentFilterDB: IntentFilterDataBase) = {
    intentFilterDB.getIntentFmap.foreach{
      case (rec, filters) =>
        if(this.intentFmap.contains(rec)){
          this.intentFmap += (rec -> (this.intentFmap(rec) ++ filters))
        } else {
          this.intentFmap += (rec -> filters)
        }
    }
  }
  def containsClass(r: JawaClass): Boolean = containsClass(r.getName)
  def containsClass(name: String): Boolean = this.intentFmap.contains(name)
  def getIntentFmap(): IMap[String, Set[IntentFilter]] = intentFmap.toMap
  def getIntentFilters(r: JawaClass): ISet[IntentFilter] = getIntentFilters(r.getName)
  def getIntentFilters(name: String): ISet[IntentFilter] = this.intentFmap.getOrElse(name, Set())
  def getIntentFiltersActions(r: JawaClass): ISet[String] = {
    val intentFilterS: ISet[IntentFilter] = getIntentFilters(r)
    val actions: MSet[String] = msetEmpty
    if(intentFilterS != null){
      intentFilterS.foreach{       
      intentFilter =>
        actions ++= intentFilter.getActions
      }      
    }
    actions.toSet
  }
  def reset = {
    this.intentFmap.clear()
    this
  }
  override def toString() = intentFmap.toString
}



class IntentFilter(holder: String) {
	private val actions: MSet[String] = msetEmpty
	private val categories: MSet[String] = msetEmpty
	private val data = new Data
    /**
     * checks if this filter can accept an intent with (action, categories, uriData, mType)
     */
	def isMatchWith(action:String, categories: Set[String], uriData:UriData, mType:String):Boolean = {
	  var actionTest = false
	  var categoryTest = false
	  var dataTest = false
	  if(action == null && categories.isEmpty && uriData == null && mType == null) return false
	  if(action == null || hasAction(action)){
	    actionTest = true
	  }
	  
//	  if(hasCategories(categories)){
//	    categoryTest = true
//	  }
	  
	  //note that in path-insensitive static analysis we had to change the category match subset rule,
	  //we ensure no false-negative (which means no match is ignored)
	  if(categories.isEmpty){
	    categoryTest = true
	  } else if(!categories.filter(c => this.categories.contains(c)).isEmpty){
	    categoryTest = true
	  }
	  
	  // note that in android there is some discrepancy regarding data and mType on the Intent side and the Intent Filter side
	  if(this.data.matchWith(uriData, mType))
	    dataTest = true
//	  println("actionTest:" + actionTest + "  categoryTest:" + categoryTest + "  dataTest:" + dataTest)
	  actionTest && categoryTest && dataTest
	}
	
	def hasAction(action:String):Boolean = {
	  this.actions.contains(action) || this.actions.contains("ANY")
	}
	def hasCategories(categories: Set[String]):Boolean = {
	  categories.subsetOf(this.categories) || this.categories.contains("ANY")
	}
	
	def addAction(action: String) = actions += action
	def addCategory(category: String) = categories += category
	def modData(scheme: String, 
	    				host: String, 
	    				port: String, 
	    				path: String, 
	    				pathPrefix: String, 
	    				pathPattern: String,
	    				mimeType: String) = {
	  data.add(scheme, host, port, path, pathPrefix, pathPattern, mimeType)
		
  }
  
  def getActions: ISet[String] = IntentFilter.this.actions.toSet
  def getCategorys: ISet[String] = IntentFilter.this.categories.toSet
  def getData: Data = IntentFilter.this.data
  def getHolder() = IntentFilter.this.holder
  
  override def toString() = "component: " + holder + " (actions: " + actions + " categories: " + categories + " datas: " + data + ")"
}

// A Data class represents all pieces of info associated with all <data> tags of a particular filter as declared in a manifest file 

class Data{
  private val schemes: MSet[String] = msetEmpty
  private val authorities: MSet[Authority] = msetEmpty
  private val paths: MSet[String] = msetEmpty
  private val pathPrefixs: MSet[String] = msetEmpty
  private val pathPatterns: MSet[String] = msetEmpty
  private val mimeTypes: MSet[String] = msetEmpty
  
  def getSchemes = schemes
  def getAuthorities = authorities
  def getPaths = paths
  def getPathPrefixs = pathPrefixs
  def getPathPatterns = pathPatterns
  def getMimeTypes = mimeTypes
  
  case class Authority(host: String, port: String)
  
  def isEmpty: Boolean = schemes.isEmpty && authorities.isEmpty && paths.isEmpty && pathPrefixs.isEmpty && pathPatterns.isEmpty && mimeTypes.isEmpty
  
  // note that in android there is some discrepancy regarding data and mType on the Intent side compared to that on the Intent Filter side
  def matchWith(uriData:UriData, mType:String):Boolean = {
    var dataTest = false
    var typeTest = false
    if(this.schemes.isEmpty && uriData == null) // **** re-check this logic
      dataTest = true
    if(uriData != null && matchWith(uriData))  // **** re-check this logic
      dataTest = true
    if(uriData != null && (uriData.getScheme == "content" || uriData.getScheme == "file")){
      if(this.schemes.isEmpty) dataTest = true
    }
    if(this.mimeTypes.isEmpty && mType == null)
      typeTest = true
    else {
      this.mimeTypes.foreach{
        ifType =>
          if(mType != null && ifType.matches("([^\\*]*|\\*)/([^\\*]*|\\*)") && mType.matches("([^\\*]*|\\*)/([^\\*]*|\\*)")){ // four cases can match: test/type, test/*, */type, */*
            val ifTypeFront = ifType.split("\\/")(0)
            val ifTypeTail = ifType.split("\\/")(1)
            val mTypeFront = mType.split("\\/")(0)
            val mTypeTail = mType.split("\\/")(1)
            var frontTest = false
            var tailTest = false
            if(ifTypeFront == mTypeFront || (ifTypeFront == "*" && mTypeFront == "*")){
              frontTest = true
            }
            if(ifTypeTail == mTypeTail || ifTypeTail == "*" || mTypeTail == "*"){
              tailTest = true
            }
            typeTest = frontTest && tailTest
          }
      }
    }
      
    dataTest && typeTest
  }
  def matchWith(uriData:UriData):Boolean = {
    val scheme = uriData.getScheme()
    val host = uriData.getHost()
    val port = uriData.getPort()
    val path = uriData.getPath()
    var schemeTest = false
    var authorityTest = false
    var pathTest = false
    var pathPrefixTest = false
    var pathPatternTest = false
    if(this.schemes.isEmpty){ // we need to extend the matching logic to include many cases
      if(scheme == null){
        schemeTest = true
        authorityTest = true
        pathTest = true
      }
    } else if(scheme != null && this.schemes.contains(scheme)){
      schemeTest = true
	    if(this.authorities.isEmpty || this.authorities.filter(a => a.host != null).isEmpty){
	      authorityTest = true
	      pathTest = true
	    } else {
	      this.authorities.foreach{
	        case Authority(if_host, if_port) =>
	          if(if_host == host){
	            if(if_port == null || if_port == port){
	              authorityTest = true
	              if(this.paths.isEmpty && this.pathPrefixs.isEmpty && this.pathPatterns.isEmpty){
	                pathTest = true
	                pathPrefixTest = true
	                pathPatternTest = true
	              } else if(path != null){
	                pathTest = this.paths.contains(path)
	                this.pathPrefixs.foreach{
	                  pre =>
	                    if(path.startsWith(pre)) pathPrefixTest = true
	                }
	                this.pathPatterns.foreach{
	                  pattern =>
	                    if(path.matches(pattern)) pathPatternTest = true
	                }
	              }
	            }
	          }
	      }
	    }
    }
//    println("schemeTest-->" + schemeTest + " authorityTest-->" + authorityTest + "(pathTest || pathPrefixTest || pathPatternTest)-->" + (pathTest || pathPrefixTest || pathPatternTest))
    schemeTest && authorityTest && (pathTest || pathPrefixTest || pathPatternTest)
  }
  
  def add(scheme: String, 
	    				host: String, 
	    				port: String, 
	    				path: String, 
	    				pathPrefix: String, 
	    				pathPattern: String, 
	    				mimeType: String) = {
    if(scheme!= null){
      this.schemes +=scheme
    }
    if(host != null || port != null){
      this.authorities += Authority(host, port)
    }
    if(path!= null){
      this.paths +=path
    }
    if(pathPrefix != null){
	    this.pathPrefixs += pathPrefix
	}
	if(pathPattern != null){
	    this.pathPatterns += pathPattern
	}
	if(mimeType != null){
	    this.mimeTypes += mimeType
	}
  }
  
  def addScheme(scheme: String) ={
    if(scheme!= null){
      this.schemes +=scheme
    }
  }
  
  def addAuthority(host: String, port: String) = {
    this.authorities += Authority(host, port)
  }
  
  def addAuthorityHostOnly(host: String) = {
    this.authorities += Authority(host, null)
  }
  
  def addAuthorityPortOnly(port: String) = {
    this.authorities += Authority(null, port)
  }
  
  def addPath(path: String) ={
    if(path!= null){
      this.paths +=path
    }
  }
  def addType(mimeType: String) ={
    if(mimeType!= null){
      this.mimeTypes +=mimeType
    }
  }
  override def toString() = {"schemes= " + schemes + " authorities= " + authorities + " path= " + paths + " pathPrefix= " + pathPrefixs + " pathPattern= " + pathPatterns + " mimeType= " + mimeTypes}
}

// A UriData class represents all pieces of info associated with the mData field of a particular Intent instance

class UriData{
  private var scheme: String = null
  private var host: String = null 
  private var port: String = null
  private var path: String = null
  private var pathPrefix: String = null
  private var pathPattern: String = null
  

  def set(scheme: String, 
	    				host: String, 
	    				port: String, 
	    				path: String, 
	    				pathPrefix: String, 
	    				pathPattern: String
	    				) = {
    if(scheme!= null){
      this.scheme =scheme
    }
    if(host!= null){
      this.host =host
    }
    if(port!= null){
      this.port =port
    }
    if(path!= null){
      this.path =path
    }
    if(pathPrefix != null){
	    this.pathPrefix = pathPrefix
		}
		if(pathPattern != null){
		    this.pathPattern = pathPattern
		}
	
  }
  
  def setScheme(scheme: String) ={
    if(scheme!= null){
      this.scheme =scheme
    }
  }
  def getScheme() = this.scheme
  
  def setHost(host: String) ={
    if(host!= null){
      this.host =host
    }
  }
  def getHost() = this.host
  def setPort(port: String) ={
    if(port!= null){
      this.port =port
    }
  }
  def getPort() = this.port
  def setPath(path: String) ={
    if(path!= null){
      this.path =path
    }
  }
  def getPath() = this.path
  
  def setPathPrefix(pathPrefix: String) ={
    if(pathPrefix!= null){
      this.pathPrefix = pathPrefix
    }
  }
  def getPathPrefix() = this.pathPrefix
  
  def setPathPattern(pathPattern: String) ={
    if(pathPattern!= null){
      this.pathPattern = pathPattern
    }
  }
  def getPathPattern() = this.pathPattern
  
  override def toString() = {"schemes= " + scheme + " host= " + host + " port= " + port + " path= " + path + " pathPrefix= " + pathPrefix + " pathPattern= " + pathPattern }
}