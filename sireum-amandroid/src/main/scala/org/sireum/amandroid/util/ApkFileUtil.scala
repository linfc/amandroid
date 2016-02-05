/*
Copyright (c) 2015-2016 Fengguo Wei, University of South Florida.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.util

import org.sireum.util.FileResourceUri
import org.sireum.util.FileUtil
import org.sireum.util.ISeq
import org.sireum.amandroid.Apk

/**
 * @author fgwei
 */
object ApkFileUtil {
  def getApks(dirUri: FileResourceUri, recursive: Boolean = true): ISeq[FileResourceUri] = {
    FileUtil.listFiles(dirUri, "", recursive).filter(Apk.isValidApk(_))
  }
}