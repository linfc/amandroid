package org.sireum.androidLibraryFile

import org.sireum.util._

trait AndroidLibraryFiles {
  val DEX_FILE_EXT = ".jar"
    
  def sourceDirUri(claz : Class[_], path : String) = { 
    FileUtil.fileUri(claz, path)
  }    
  
  def androidLibraryFiles(dirUri : FileResourceUri,
                   ext : String = DEX_FILE_EXT) : ISeq[FileResourceUri] =
    FileUtil.listFiles(dirUri, ext, true)
}

trait AndroidLibraryDexFiles {
  val DEX_FILE_EXT = ".dex"
    
  def sourceDirUri(claz : Class[_], path : String) = { 
    FileUtil.fileUri(claz, path)
  }    
  
  def androidLibraryFiles(dirUri : FileResourceUri,
                   ext : String = DEX_FILE_EXT) : ISeq[FileResourceUri] =
    FileUtil.listFiles(dirUri, ext, true)
}

trait AndroidLibraryPilarFiles {
  val PILAR_FILE_EXT = ".pilar"
    
  def sourceDirUri(claz : Class[_], path : String) = { 
    FileUtil.fileUri(claz, path)
  }    
  
  def androidLibraryFiles(dirUri : FileResourceUri,
                   ext : String = PILAR_FILE_EXT) : ISeq[FileResourceUri] =
    FileUtil.listFiles(dirUri, ext, true)
}

trait AndroidLibrarySplitPilarFiles {
  val PLR_FILE_EXT = ".plr"
    
  def sourceDirUri(claz : Class[_], path : String) = { 
    FileUtil.fileUri(claz, path)
  }    
  
  def androidLibraryFiles(dirUri : FileResourceUri,
                   ext : String = PLR_FILE_EXT) : ISeq[FileResourceUri] =
    FileUtil.listFiles(dirUri, ext, true)
}

trait AndroidLibraryXmlFiles {
  val XML_FILE_EXT = ".xml"
    
  def sourceDirUri(claz : Class[_], path : String) = { 
    FileUtil.fileUri(claz, path)
  }    
  
  def androidLibraryFiles(dirUri : FileResourceUri,
                   ext : String = XML_FILE_EXT) : ISeq[FileResourceUri] =
    FileUtil.listFiles(dirUri, ext, true)
}