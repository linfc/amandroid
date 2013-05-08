package org.sireum.amandroid.util

import org.sireum.util._

class SignatureParser(sig : String) {
  
  private class ParameterSignatureIterator extends Iterator[String] {
        private var index = 1;

        def hasNext() : Boolean = {
            return index < signature.length() && signature.charAt(index) != ')';
        }

        def next() : String = {
            if (!hasNext())
                throw new NoSuchElementException();
            val result = new StringBuilder();
            var done : Boolean = false;
            do {
                done = true;
                val ch = signature.charAt(index);
                ch match {
                  case 'B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z' =>
                      result.append(signature.charAt(index));
                      index+=1;
                  case 'L' =>
                      val semi = signature.indexOf(';', index + 1);
                      if (semi < 0)
                          throw new IllegalStateException("Invalid method signature: " + signature);
                      result.append(signature.substring(index, semi + 1));
                      index = semi + 1;
                  case '[' =>
                      result.append('[');
                      index+=1;
                      done = false;
                  case _ =>
                      throw new IllegalStateException("Invalid method signature: " + signature);
                }
            } while (!done);

            return result.toString();
        }

        def remove() = {
            throw new UnsupportedOperationException();
        }
    }
  
    /**
     * Get the method return type signature.
     * 
     * @return the method return type signature
     */
    def getReturnTypeSignature() : String = {
      val endOfParams = signature.lastIndexOf(')')
      if (endOfParams < 0)
        throw new IllegalArgumentException("Bad method signature: " + signature);
      return signature.substring(endOfParams + 1);
    }
  
    def getParameters() : MList[String] = {
        var count = 0;
        val params : MList[String] = mlistEmpty
        val iterator = new ParameterSignatureIterator()
        while(iterator.hasNext){
          val p = iterator.next();
          params.insert(count, p)
          count+=1;
        }
        params
    }
    
    //before cut: [|LSavings;.interest:(I)V|], after cut: (I)V
    def getParamSig = {
      signature = signature.substring(signature.indexOf(':') + 1, signature.length()-2)
      this
    }

    private var signature : String = sig
}