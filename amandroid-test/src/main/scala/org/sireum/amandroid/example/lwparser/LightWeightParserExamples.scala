package org.sireum.amandroid.example.lwparser

import org.sireum.amandroid.example.Examples



/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */
object LightWeightParserExamples extends Examples{
	val PILAR_MODEL_DIR_URI = sourceDirUri(this.getClass, "./pilar/model/") 
  val ANDROID_PILAR_FILE_EXT = ".pilar"
  def pilarModelFiles = exampleFiles(PILAR_MODEL_DIR_URI, ANDROID_PILAR_FILE_EXT)
}