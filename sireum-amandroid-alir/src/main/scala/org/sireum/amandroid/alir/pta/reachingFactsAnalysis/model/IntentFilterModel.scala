/*
Copyright (c) 2013-2014 Fengguo Wei & Sankardas Roy, Kansas State University.        
All rights reserved. This program and the accompanying materials      
are made available under the terms of the Eclipse Public License v1.0 
which accompanies this distribution, and is available at              
http://www.eclipse.org/legal/epl-v10.html                             
*/
package org.sireum.amandroid.alir.pta.reachingFactsAnalysis.model

import org.sireum.jawa._
import org.sireum.util._
import org.sireum.jawa.alir.Context
import org.sireum.jawa.alir.pta.reachingFactsAnalysis._
import org.sireum.amandroid.AndroidConstants
import org.sireum.jawa.MessageCenter._
<<<<<<< HEAD:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/model/IntentFilterModel.scala
import org.sireum.jawa.alir.pta.UnknownInstance
import org.sireum.jawa.alir.pta.NullInstance
import org.sireum.jawa.alir.pta.PTAPointStringInstance
import org.sireum.jawa.alir.pta.PTAConcreteStringInstance
import org.sireum.jawa.alir.pta.PTAResult
import org.sireum.jawa.alir.pta.FieldSlot
import org.sireum.jawa.util.StringFormConverter
import org.sireum.jawa.alir.pta.VarSlot
=======
import org.sireum.jawa.alir.UnknownInstance
import org.sireum.jawa.alir.NullInstance
import org.sireum.jawa.alir.pta.PTAPointStringInstance
import org.sireum.jawa.alir.pta.PTAConcreteStringInstance
>>>>>>> CommunicationLeakage:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/model/IntentFilterModel.scala

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object IntentFilterModel {
  
  final val TITLE = "IntentFilterModel"
  
	def isIntentFilter(r : JawaClass) : Boolean = r.getName == AndroidConstants.INTENTFILTER
	  
	def doIntentFilterCall(s : PTAResult, p : JawaMethod, args : List[String], retVars : Seq[String], currentContext : Context) : (ISet[RFAFact], ISet[RFAFact], Boolean) = {
	  var newFacts = isetEmpty[RFAFact]
	  var delFacts = isetEmpty[RFAFact]
	  var byPassFlag = true
	  p.getSignature match{
	    case "Landroid/content/IntentFilter;.<clinit>:()V" =>  //static constructor
		  case "Landroid/content/IntentFilter;.<init>:()V" =>  //public constructor
		  case "Landroid/content/IntentFilter;.<init>:(Landroid/content/IntentFilter;)V" =>  //public constructor
		  case "Landroid/content/IntentFilter;.<init>:(Landroid/os/Parcel;)V" =>  //private constructor
		  case "Landroid/content/IntentFilter;.<init>:(Landroid/os/Parcel;Landroid/content/IntentFilter$1;)V" =>  //synthetic constructor
		  case "Landroid/content/IntentFilter;.<init>:(Ljava/lang/String;)V" =>  //public constructor
		    intentFilterInitWithAction(s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
		    byPassFlag = false
		  case "Landroid/content/IntentFilter;.<init>:(Ljava/lang/String;Ljava/lang/String;)V" =>  //public constructor
		  case "Landroid/content/IntentFilter;.actionsIterator:()Ljava/util/Iterator;" =>  //public final
		  case "Landroid/content/IntentFilter;.addAction:(Ljava/lang/String;)V" =>  //public final
		  case "Landroid/content/IntentFilter;.addCategory:(Ljava/lang/String;)V" =>  //public final
		  case "Landroid/content/IntentFilter;.addDataAuthority:(Ljava/lang/String;Ljava/lang/String;)V" =>  //public final
		  case "Landroid/content/IntentFilter;.addDataPath:(Ljava/lang/String;I)V" =>  //public final
		  case "Landroid/content/IntentFilter;.addDataScheme:(Ljava/lang/String;)V" =>  //public final
		  case "Landroid/content/IntentFilter;.addDataType:(Ljava/lang/String;)V" =>  //public final
		  case "Landroid/content/IntentFilter;.addStringToSet:([Ljava/lang/String;Ljava/lang/String;[II)[Ljava/lang/String;" =>  //private static
		  case "Landroid/content/IntentFilter;.authoritiesIterator:()Ljava/util/Iterator;" =>  //public final
		  case "Landroid/content/IntentFilter;.categoriesIterator:()Ljava/util/Iterator;" =>  //public final
		  case "Landroid/content/IntentFilter;.countActions:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.countCategories:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.countDataAuthorities:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.countDataPaths:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.countDataSchemes:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.countDataTypes:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.create:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/IntentFilter;" =>  //public static
		  case "Landroid/content/IntentFilter;.debugCheck:()Z" =>  //public
		  case "Landroid/content/IntentFilter;.describeContents:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.dump:(Landroid/util/Printer;Ljava/lang/String;)V" =>  //public
		  case "Landroid/content/IntentFilter;.findMimeType:(Ljava/lang/String;)Z" =>  //private final
		  case "Landroid/content/IntentFilter;.findStringInSet:([Ljava/lang/String;Ljava/lang/String;[II)I" =>  //private static
		  case "Landroid/content/IntentFilter;.getAction:(I)Ljava/lang/String;" =>  //public final
		  case "Landroid/content/IntentFilter;.getCategory:(I)Ljava/lang/String;" =>  //public final
		  case "Landroid/content/IntentFilter;.getDataAuthority:(I)Landroid/content/IntentFilter$AuthorityEntry;" =>  //public final
		  case "Landroid/content/IntentFilter;.getDataPath:(I)Landroid/os/PatternMatcher;" =>  //public final
		  case "Landroid/content/IntentFilter;.getDataScheme:(I)Ljava/lang/String;" =>  //public final
		  case "Landroid/content/IntentFilter;.getDataType:(I)Ljava/lang/String;" =>  //public final
		  case "Landroid/content/IntentFilter;.getPriority:()I" =>  //public final
		  case "Landroid/content/IntentFilter;.hasAction:(Ljava/lang/String;)Z" =>  //public final
		  case "Landroid/content/IntentFilter;.hasCategory:(Ljava/lang/String;)Z" =>  //public final
		  case "Landroid/content/IntentFilter;.hasDataAuthority:(Landroid/net/Uri;)Z" =>  //public final
		  case "Landroid/content/IntentFilter;.hasDataPath:(Ljava/lang/String;)Z" =>  //public final
		  case "Landroid/content/IntentFilter;.hasDataScheme:(Ljava/lang/String;)Z" =>  //public final
		  case "Landroid/content/IntentFilter;.hasDataType:(Ljava/lang/String;)Z" =>  //public final
		  case "Landroid/content/IntentFilter;.match:(Landroid/content/ContentResolver;Landroid/content/Intent;ZLjava/lang/String;)I" =>  //public final
		  case "Landroid/content/IntentFilter;.match:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;Ljava/util/Set;Ljava/lang/String;)I" =>  //public final
		  case "Landroid/content/IntentFilter;.matchAction:(Ljava/lang/String;)Z" =>  //public final
		  case "Landroid/content/IntentFilter;.matchCategories:(Ljava/util/Set;)Ljava/lang/String;" =>  //public final
		  case "Landroid/content/IntentFilter;.matchData:(Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;)I" =>  //public final
		  case "Landroid/content/IntentFilter;.matchDataAuthority:(Landroid/net/Uri;)I" =>  //public final
		  case "Landroid/content/IntentFilter;.pathsIterator:()Ljava/util/Iterator;" =>  //public final
		  case "Landroid/content/IntentFilter;.readFromXml:(Lorg/xmlpull/v1/XmlPullParser;)V" =>  //public
		  case "Landroid/content/IntentFilter;.removeStringFromSet:([Ljava/lang/String;Ljava/lang/String;[II)[Ljava/lang/String;" =>  //private static
		  case "Landroid/content/IntentFilter;.schemesIterator:()Ljava/util/Iterator;" =>  //public final
		  case "Landroid/content/IntentFilter;.setPriority:(I)V" =>  //public final
		  case "Landroid/content/IntentFilter;.typesIterator:()Ljava/util/Iterator;" =>  //public final
		  case "Landroid/content/IntentFilter;.writeToParcel:(Landroid/os/Parcel;I)V" =>  //public final
		  case "Landroid/content/IntentFilter;.writeToXml:(Lorg/xmlpull/v1/XmlSerializer;)V" =>  //public
	  }
	  (newFacts, delFacts, byPassFlag)
	}
  
  
	/**
	 * Landroid/content/IntentFilter;.<init>:(Ljava/lang/String;)V
	 */
	private def intentFilterInitWithAction(s : PTAResult, args : List[String], currentContext : Context) : (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args(0))
	  val thisValue = s.pointsToSet(thisSlot, currentContext)
	  val actionSlot = VarSlot(args(1))
	  val actionValue = s.pointsToSet(actionSlot, currentContext)
	  var newfacts = isetEmpty[RFAFact]
    var delfacts = isetEmpty[RFAFact]
	  thisValue.foreach{
	    tv =>
	      if(thisValue.size == 1){
          for(v <- s.pointsToSet(FieldSlot(tv, StringFormConverter.getFieldNameFromFieldSignature(AndroidConstants.INTENTFILTER_ACTIONS)), currentContext)){
            delfacts += RFAFact(FieldSlot(tv, StringFormConverter.getFieldNameFromFieldSignature(AndroidConstants.INTENTFILTER_ACTIONS)), v)
          }
	      }
	      actionValue.foreach{
		      acStr =>
	          acStr match{
	            case cstr @ PTAConcreteStringInstance(text, c) =>
<<<<<<< HEAD:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/model/IntentFilterModel.scala
	              newfacts += RFAFact(FieldSlot(tv, StringFormConverter.getFieldNameFromFieldSignature(AndroidConstants.INTENTFILTER_ACTIONS)), cstr)
=======
	              newfacts += RFAFact(FieldSlot(tv, AndroidConstants.INTENTFILTER_ACTIONS), cstr)
>>>>>>> CommunicationLeakage:sireum-amandroid-alir/src/main/scala/org/sireum/amandroid/alir/pta/reachingFactsAnalysis/model/IntentFilterModel.scala
	            case pstr @ PTAPointStringInstance(c) => 
	              err_msg_detail(TITLE, "Init IntentFilter use point string: " + pstr)
	              newfacts += RFAFact(FieldSlot(tv, StringFormConverter.getFieldNameFromFieldSignature(AndroidConstants.INTENTFILTER_ACTIONS)), pstr)
	            case ustr @ UnknownInstance(t, c) => 
	            case ustr @ NullInstance(c) => 
	            case _ => throw new RuntimeException("unexpected instance type: " + acStr)
	          }
		    }
	  }
    (newfacts, delfacts)
  }
	
}