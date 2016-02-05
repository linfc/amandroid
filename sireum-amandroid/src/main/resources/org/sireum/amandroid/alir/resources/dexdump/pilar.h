// ****** sankar introduces pilar.h which is to be included with DexDump.cpp; It also includes some of Kui's previous modification on DexDump.cpp ************* 


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <errno.h>
#define DEFAULT_MODE      S_IRWXU | S_IRGRP |  S_IXGRP | S_IROTH | S_IXOTH  // used in mkdirp() which creates directory
#define PILAR_EXT ".pilar"
/*
 * replace character 'a' by another char 'b' (for all occurrences of 'a') in a string
 */
static char* replaceChar(const char* str, char a, char b)
{
  char* mystring = (char*)malloc(strlen(str) + 1);
  strcpy(mystring, str);
  for (unsigned int count = 0; count < strlen(mystring); count++)
  {
    if (mystring[count] == a)
     {
       mystring[count] = b;
     }
  }
  return mystring;
}

/* sankar adds toPilar: This func reformats a class descritptor to the pilar format.  For
 * example, "int[]" becomes "`int`[]".
 */
static char* toPilar(const char* str)
{
    int targetLen = strlen(str) + 2; // `...` are extra 2 chars
    int offset = strlen(str) - 1;
    int arrayDepth = 0;
    char* newStr = (char*)malloc(targetLen + 1);   // source of memory leak as this space is never freed  

    /* strip trailing []s; this will again be added to end */
    while (offset > 1) {
		if(str[offset] == ']' && str[offset - 1] == '[')
         { 
			 offset = offset - 2;
			 arrayDepth++;
		 }

		 else
			 break;
        
    }
    


    /* brace with ` ` i.e. copy class name in the middle */

    int i = 0;
    newStr[0] = '`';
	i = 1;
    for (int j = 0; j <= offset; j++) {
         char ch = str[j];
         newStr[j+1]=ch;
		 i++;
    }

    newStr[i++] = '`';

    for(int j = 0; j<arrayDepth; j++) {
	
	     newStr[i] = '[';
		 newStr[i+1] = ']';
		 i = i + 2;
		
    }

    newStr[i] = '\0';
    assert(i == targetLen);
    return newStr;
}

/* fengguo adds toPilarArrayBaseType: This func reformats a class descritptor to the pilar format.  For
 * example, "int[][]" becomes "`int`[]".
 */
static char* toPilarArrayBaseType(const char* str)
{
	int targetLen = strlen(str) + 2; // `...` are extra 2 chars
	int offset = strlen(str) - 1;
	int arrayDepth = 0;
	char* newStr = (char*)malloc(targetLen + 1);   // source of memory leak as this space is never freed

	/* strip trailing []s; this will again be added to end */
	while (offset > 1) {
		if(str[offset] == ']' && str[offset - 1] == '[')
		 {
			 offset = offset - 2;
			 arrayDepth++;
		 }

		 else
			 break;
	}
	/* brace with ` ` i.e. copy class name in the middle */

	int i = 0;
	newStr[0] = '`';
	i = 1;
	for (int j = 0; j <= offset; j++) {
		 char ch = str[j];
		 newStr[j+1]=ch;
		 i++;
	}

	newStr[i++] = '`';

	for(int j = 0; j<arrayDepth - 1; j++) {
		 newStr[i] = '[';
		 newStr[i+1] = ']';
		 i = i + 2;
	}

	newStr[i] = '\0';
	assert(i == targetLen);
	return newStr;
}

/* sankar adds toPilarS: This func reformats a class descritptor to the pilar format.  S stands for special reformat. For
 * example, "byte[v3]" becomes "`byte`[v3]".
 */
static char* toPilarS(const char* str)
{
    int targetLen = strlen(str) + 2; // ` ` are extra 2 chars
    int offset = 0;
    int leng = strlen(str);
    char* newStr = (char*)malloc(targetLen + 1); // source of memory leak as this space is never freed;
    bool arrayFlag = false;

    /* move the offset to the first [ of trailing []s or [v1]s */
    while(offset < leng){
       if(str[offset] == '['){
		 arrayFlag = true;
		 break;
	   }
	   offset++;
	}
    /* brace with ` ` i.e. copy class name in the middle */

    int i = 0;
    newStr[0] = '`';
	i = 1;
    for (int j = 0; j < offset; j++) {
         char ch = str[j];
         newStr[j+1]=ch;
		 i++;
    }

    newStr[i++] = '`';

    for(int j = offset; j < leng; j++) {
	     char ch = str[j];
	     newStr[i] = ch;
		 i++;
    }

    newStr[i] = '\0';
    assert(i == targetLen);
    return newStr;
}

struct locVarInfo {  // sankar adds this struct which can store one local variable info 
	
	char* descriptor;
	char* name;
	u2 reg;
	u4 startAddress;
	u4 endAddress;
    bool paramFlag; // if true then it indicates that this local variable is also a parameter of the procedure

    locVarInfo(const char* desc, const char* nam, u2 r, u4 sa, u4 ea)
	 { 
	  descriptor = new char[strlen(desc) + 1];
	  strcpy(descriptor, desc);
	  name = new char[strlen(nam) + 1];
	  strcpy(name, nam);
	  reg = r;
      startAddress = sa;
	  endAddress = ea;
	  paramFlag = false;  // if param, then this flag will be set in dumpMethod() function of DexDump.cpp
	 }

	~locVarInfo()
    	{
	    	delete descriptor;
		    delete name;
        } 

	};


//******************* kui's modification begins  *******************
struct Op31t {
    int insnIdx;
    const DecodedInstruction* pDecInsn;

	u4 vA; // sankar adds to ensure that pDecInsn->vA is available later; not only immediate after invoking init()
	u4 vB; // sankar adds to ensure that pDecInsn->vB is available later; not only immediate after invoking init()

    Op31t(int insnIdx,const DecodedInstruction* pDecInsn){
      this->insnIdx=insnIdx;
      this->pDecInsn=pDecInsn;

	  assert(pDecInsn);        // sankar adds
	  this->vA = pDecInsn->vA; // sankar adds
	  this->vB = pDecInsn->vB; // sankar adds
    }
};
//******************* kui's modification ends  *******************

/*
 * Creates directory in a path; returns "true" if successful, and "false" otherwise.
 * It returns "false" only when some serious error happens.
 */


bool mkdirp(const char* path, mode_t mode = DEFAULT_MODE) {

            char* q = (char*)malloc(strlen(path) + 1);
            strcpy(q, path); // a copy of "path", which gets modified and restored again and again
            char* p = q; // p traverses along string q

           // Do mkdir for each slash until end of string q or error
            while (*p != '\0') {
               // Skip first character
                p++;

               // Find first slash or end
                while(*p != '\0' && *p != '/') p++;

                // Remember value from p
                char v = *p;

                // Write end of string at p
                *p = '\0';

                // Create directory:"from beginning to current p" (note that '\0' was inserted at p)
                if(mkdir(q, mode) == -1 && errno != EEXIST) {
                    // enters inside the condition only when some serious error happens
                    // if the directory already exists, then errno=EEXIST and we do not enter inside
                   *p = v;
                   if(q)
                     delete q;
                   return false;
                }

                // Restore string q to the orginal path
                *p = v;
            }
            if(q)
              delete q;
            return true;
}


/*
 * Extracts the package directory name from a class descriptor.
 *
 * Returns a newly-allocated string.
 */
static char* dirName(const char* str)
{
    const char* lastDot;
    char* dir;
    int length = 0;
    lastDot = strrchr(str, '.');
    if ((lastDot == NULL) || (lastDot == str))
        {
			dir = (char*)malloc(length + 1);
			dir[length] = '\0';
	    }
    else
        {
			assert(lastDot > str);
			length = lastDot - str;
			dir = (char*)malloc(length + 1); // lastDot - str = length of "directory" part;
		    strncpy(dir, str, length);	// copy the "directory" part from str to newStr
		    dir[length]='\0';
        }
    return dir;
}



/*
 * Extracts the class part from a class descriptor.
 *
 * Returns a newly-allocated string.
 */
static char* className(const char* str)
{
    const char* lastDot;
    char* cName;
    int length = 0;

    lastDot = strrchr(str, '.');
    if ((lastDot == NULL) || (lastDot == str))
        {
			length = strlen(str);
			cName = (char*)malloc(length + 1);
			strncpy(cName, str, length);
			cName[length] = '\0';
	    }
    else
        {
			assert(lastDot > str);
			length = strlen(lastDot + 1);
			cName = (char*)malloc(length + 1); // length of "class" part;
		    strncpy(cName, lastDot+1, length);	// copy the "class" part from str to cName
		    cName[length] = '\0';
        }
    return cName;
}



/*
 * Extracts the name portion from the input (app) filename, name.ext.
 * If no ".ext" is found in input string, then raise error. Otherwise, it constructs a string, "name".
 *
 * Returns a newly-allocated string.
 */
static char* pilarDirName(const char* str)
{
    const char* lastDot;
    char* dir;
    int length = 0;


    lastDot = strrchr(str, '.');
    if ((lastDot == NULL) || (lastDot == str))
        {
			fprintf(stderr,"the input file name has to be of the form name.apk or name.dex");
			exit(1);

	    }
    else
        {
			assert(lastDot > str);
			length = lastDot - str;
			dir = (char*)malloc(length + 1); // length of "name" part;
		    strncpy(dir, str, length);	// copy the name portion from str to dir
		    dir[length] = '\0';
        }

    return dir;
}


/*
 * Extracts the name portion from the input (app) filename, name.ext.
 * If no ".ext" is found in input string, then raise error. Otherwise, it constructs a string, "name.pilar".
 *
 * Returns a newly-allocated string.
 */
static char* pilarExtName(const char* str)
{
    const char* lastDot;
    char* newStr;
    int length = 0;

    lastDot = strrchr(str, '.');
    if ((lastDot == NULL) || (lastDot == str))
        { 
			fprintf(stderr,"the input file name has to be of the form name.ext"); 
			exit(1);
			
	    }        
    else
        { 
			assert(lastDot > str);
			length = lastDot - str;
			newStr = (char*)malloc(length + strlen(PILAR_EXT));
		    strncpy(newStr, str, length);	// copy the name portion from str to newStr
		    newStr[length]='\0';
			strcat(newStr, PILAR_EXT);
        }                

    return newStr;
}

 #define  outMove(x, y)            fprintf(pFp,"v%d:= v%d;", x, y)
 #define  outMoveWide(x, y)        fprintf(pFp,"v%d:= v%d  @kind long;", x, y)
 #define  outMoveObject(x, y)      fprintf(pFp,"v%d:= v%d  @kind object;", x, y)
 #define  outMoveResult(x)         fprintf(pFp,"v%d:= temp;", x)
 #define  outMoveResultWide(x)     fprintf(pFp,"v%d:= temp  @kind long;", x)
 #define  outMoveResultObject(x)   fprintf(pFp,"v%d:= temp  @kind object;", x)
 #define  outMoveExc(x)            fprintf(pFp,"v%d:= Exception  @kind object;", x)
 #define  outReturnVoid()          fprintf(pFp,"return  @kind void;")
 #define  outReturn(x)             fprintf(pFp,"return v%d;", x)
 #define  outReturnWide(x)         fprintf(pFp,"return v%d  @kind long;", x)
 #define  outReturnObj(x)          fprintf(pFp,"return v%d  @kind object;", x);
 #define  outConst4(x, y)          fprintf(pFp,"v%d:= %dI  @kind int;", x, y)
 #define  outConst16(x, y)         fprintf(pFp,"v%d:= %dI  @kind int;", x, y)
 #define  outConst32(x, y)         fprintf(pFp,"v%d:= %dI  @kind int;", x, y)
 #define  outConstHigh16(x, y)     fprintf(pFp,"v%d:= %dI  @kind int;", x, y)
 #define  outConstWide16(x, y)     fprintf(pFp,"v%d:= %dI  @kind int;", x, y)
 #define  outConstWide32(x, y)     fprintf(pFp,"v%d:= %fF  @kind float;", x, y)
// #define  outConstWide(x, y)       fprintf(pFp,"v%d:= %fL  @length wide;", x, y)
 #define  outConstWideHigh16(x, y) fprintf(pFp,"v%d:= %lldL  @kind long;", x, y)
 #define  outConstWide(x, y)       fprintf(pFp,"v%d:= %fD  @kind double;", x, y)
// #define  outConstWideHigh16(x, y) fprintf(pFp,"v%d:= %lld  @length wide_high16;", x, y)
 #define  outConstString(x, y)     fprintf(pFp,"v%d:= \"%s\" @kind object;", x, y)  // adding annotation in pilar for const string to treat it as object
 #define  outConstClass(x, y)      fprintf(pFp,"v%d:= constclass @type ^%s @kind object;", x, toPilar(y))
 #define  outMonitorEnter(x)       fprintf(pFp,"@monitorenter v%d", x)
 #define  outMonitorExit(x)        fprintf(pFp,"@monitorexit v%d", x)
 #define  outCheckCast(x, y, z)    fprintf(pFp,"v%d:= (%s)v%d  @kind object;", x, toPilar(y), z)
 #define  outInstanceOf(x, y, z)   fprintf(pFp,"v%d:= instanceof @variable v%d @type ^%s @kind boolean;", x, y, toPilar(z))
// #define  outArrayLen(x, y)        fprintf(pFp,"v%d:= v%d.length;", x, y)
 #define  outArrayLen(x, y)        fprintf(pFp,"v%d:= length @variable v%d @kind int;", x, y)
 #define  outNewIns(x, y)          fprintf(pFp,"v%d:= new %s;", x, toPilar(y))
 #define  outNewArray(x, y)        fprintf(pFp,"v%d:= new %s;", x, toPilarS(y))


 #define  outFilledNewArray(x, y, z)  {\
                                        fprintf(pFp,"temp:= new %s[", toPilarArrayBaseType(x)); \
                                        for (i = 0; i < (int) y; i++) { \
                                         if (i == 0) \
                                            fprintf(pFp,"v%d", z[i]); \
                                         else \
                                            fprintf(pFp,", v%d", z[i]); \
                                        } \
                                        fprintf(pFp,"];"); \
                                      }


#define outFilledNewArrRange(x, y, z)   {\
                                         fprintf(pFp,"temp:= new %s[", toPilarArrayBaseType(x));\
                                         for (i = 0; i < (int) y; i++) {\
                                             if (i == 0)\
                                                fprintf(pFp,"v%d", z + i);\
                                             else \
                                                fprintf(pFp,", v%d", z + i);\
                                         }\
                                         fprintf(pFp,"];");\
                                        } 

#define  outFillArrData(x)         	fprintf(pFp,"goto L%06x;", x)

#define outThrow(x)                	fprintf(pFp,"throw v%d;", x)

#define outGoto(x)                 	fprintf(pFp,"goto L%06x;", x)
#define outSwitch(x)               	fprintf(pFp,"goto L%06x;", x)
#define outFcmpl(x, y, z)           fprintf(pFp,"v%d:= fcmpl(v%d,v%d);", x, y, z)
#define outDcmpl(x, y, z)           fprintf(pFp,"v%d:= dcmpl(v%d,v%d);", x, y, z)
#define outFcmpg(x, y, z)           fprintf(pFp,"v%d:= fcmpg(v%d,v%d);", x, y, z)
#define outDcmpg(x, y, z)           fprintf(pFp,"v%d:= dcmpg(v%d,v%d);", x, y, z)
#define outLcmp(x, y, z)            fprintf(pFp,"v%d:= lcmp(v%d,v%d);", x, y, z)
#define outIfEq(x, y, z)           	fprintf(pFp,"if v%d == v%d then goto L%06x;", x, y, z)
#define outIfNq(x, y, z)           	fprintf(pFp,"if v%d != v%d then goto L%06x;", x, y, z)
#define outIfLt(x, y, z)           	fprintf(pFp,"if v%d < v%d then goto L%06x;", x, y, z)
#define outIfGe(x, y, z)           	fprintf(pFp,"if v%d >= v%d then goto L%06x;", x, y, z)
#define outIfGt(x, y, z)           	fprintf(pFp,"if v%d > v%d then goto L%06x;", x, y, z)
#define outIfLe(x, y, z)           	fprintf(pFp,"if v%d <= v%d then goto L%06x;", x, y, z)
#define outIfEqz(x, y)             	fprintf(pFp,"if v%d == 0 then goto L%06x;", x, y)
#define outIfNez(x, y)             	fprintf(pFp,"if v%d != 0 then goto L%06x;", x, y)
#define outIfLtz(x, y)             	fprintf(pFp,"if v%d < 0 then goto L%06x;", x, y)
#define outIfGez(x, y)             	fprintf(pFp,"if v%d >= 0 then goto L%06x;", x, y)
#define outIfGtz(x, y)             	fprintf(pFp,"if v%d > 0 then goto L%06x;", x, y)
#define outIfLez(x, y)             	fprintf(pFp,"if v%d <= 0 then goto L%06x;", x, y)

#define  outAget(x, y, z)          	fprintf(pFp,"v%d:= v%d[v%d]  @kind int;", x, y, z)
#define  outAgetWide(x, y, z)      	fprintf(pFp,"v%d:= v%d[v%d]  @kind long;", x, y, z)
#define  outAgetObject(x, y, z)    	fprintf(pFp,"v%d:= v%d[v%d]  @kind object;", x, y, z)
#define  outAgetBool(x, y, z)      	fprintf(pFp,"v%d:= v%d[v%d]  @kind boolean;", x, y, z)
#define  outAgetByte(x, y, z)      	fprintf(pFp,"v%d:= v%d[v%d]  @kind byte;", x, y, z)
#define  outAgetChar(x, y, z)      	fprintf(pFp,"v%d:= v%d[v%d]  @kind char;", x, y, z)
#define  outAgetShort(x, y, z)     	fprintf(pFp,"v%d:= v%d[v%d]  @kind short;", x, y, z)


#define  outAput(x, y, z)          	fprintf(pFp,"v%d[v%d]:= v%d  @kind int;", x, y, z)
#define  outAputWide(x, y, z)      	fprintf(pFp,"v%d[v%d]:= v%d  @kind long;", x, y, z)
#define  outAputObject(x, y, z)    	fprintf(pFp,"v%d[v%d]:= v%d  @kind object;", x, y, z)
#define  outAputBool(x, y, z)      	fprintf(pFp,"v%d[v%d]:= v%d  @kind boolean;",x, y, z)
#define  outAputByte(x, y, z)      	fprintf(pFp,"v%d[v%d]:= v%d  @kind byte;",x, y, z)
#define  outAputChar(x, y, z)      	fprintf(pFp,"v%d[v%d]:= v%d  @kind char;", x, y, z)
#define  outAputShort(x, y, z)     	fprintf(pFp,"v%d[v%d]:= v%d  @kind short;", x, y, z)
         
		 
		 
#define  outIget(x, y, z, t)          	fprintf(pFp,"v%d:= v%d.%s  @kind int @type ^%s;", x, y, z, toPilar(t))
#define  outIgetWide(x, y, z, t)      	fprintf(pFp,"v%d:= v%d.%s  @kind long @type ^%s;", x, y, z, toPilar(t))
#define  outIgetObject(x, y, z, t)    	fprintf(pFp,"v%d:= v%d.%s  @kind object @type ^%s;",x, y, z, toPilar(t))
#define  outIgetBool(x, y, z, t)      	fprintf(pFp,"v%d:= v%d.%s  @kind boolean @type ^%s;",x, y, z, toPilar(t))
#define  outIgetByte(x, y, z, t)      	fprintf(pFp,"v%d:= v%d.%s  @kind byte @type ^%s;",x, y, z, toPilar(t))
#define  outIgetChar(x, y, z, t)      	fprintf(pFp,"v%d:= v%d.%s  @kind char @type ^%s;",x, y, z, toPilar(t))
#define  outIgetShort(x, y, z, t)     	fprintf(pFp,"v%d:= v%d.%s  @kind short @type ^%s;", x, y, z, toPilar(t))
        
#define  outIgetQuick(x, y, z, t)       fprintf(pFp,"v%d:= v%d.%s  @kind int @type ^%s;", x, y, z, toPilar(t))
#define  outIgetWideQuick(x, y, z, t)   fprintf(pFp,"v%d:= v%d.%s  @kind long @type ^%s;", x, y, z, toPilar(t))
#define  outIgetObjectQuick(x, y, z, t) fprintf(pFp,"v%d:= v%d.%s  @kind object @type ^%s;",x, y, z, toPilar(t))
		
#define  outIput(x, y, z, t)          	fprintf(pFp,"v%d.%s:= v%d  @kind int @type ^%s;", x, y, z, toPilar(t))
#define  outIputWide(x, y, z, t)      	fprintf(pFp,"v%d.%s:= v%d  @kind long @type ^%s;", x, y, z, toPilar(t))
#define  outIputObject(x, y, z, t)    	fprintf(pFp,"v%d.%s:= v%d  @kind object @type ^%s;", x, y, z, toPilar(t))
#define  outIputBool(x, y, z, t)      	fprintf(pFp,"v%d.%s:= v%d  @kind boolean @type ^%s;", x, y, z, toPilar(t))
#define  outIputByte(x, y, z, t)      	fprintf(pFp,"v%d.%s:= v%d  @kind byte @type ^%s;", x, y, z, toPilar(t))
#define  outIputChar(x, y, z, t)      	fprintf(pFp,"v%d.%s:= v%d  @kind char @type ^%s;", x, y, z, toPilar(t))
#define  outIputShort(x, y, z, t)     	fprintf(pFp,"v%d.%s:= v%d  @kind short @type ^%s;", x, y, z, toPilar(t))
 

#define  outIputQuick(x, y, z, t)       fprintf(pFp,"v%d.%s:= v%d  @kind int @type ^%s;", x, y, z, toPilar(t))
#define  outIputWideQuick(x, y, z, t)   fprintf(pFp,"v%d.%s:= v%d  @kind long @type ^%s;", x, y, z, toPilar(t))
#define  outIputObjectQuick(x, y, z, t) fprintf(pFp,"v%d.%s:= v%d  @kind object @type ^%s;", x, y, z, toPilar(t))

#define  outSget(x, y, z)    			fprintf(pFp,"v%d:= %s  @kind int @type ^%s;", x, y, toPilar(z))
#define  outSgetWide(x, y, z)  			fprintf(pFp,"v%d:= %s  @kind long @type ^%s;", x, y, toPilar(z))
#define  outSgetObject(x, y, z)  		fprintf(pFp,"v%d:= %s  @kind object @type ^%s;", x, y, toPilar(z))
#define  outSgetBool(x, y, z)  			fprintf(pFp,"v%d:= %s  @kind boolean @type ^%s;", x, y, toPilar(z))
#define  outSgetByte(x, y, z)  			fprintf(pFp,"v%d:= %s  @kind byte @type ^%s;", x, y, toPilar(z))
#define  outSgetChar(x, y, z)  			fprintf(pFp,"v%d:= %s  @kind char @type ^%s;", x, y, toPilar(z))
#define  outSgetShort(x, y, z)  		fprintf(pFp,"v%d:= %s  @kind short @type ^%s;", x, y, toPilar(z))
          
#define  outSput(x, y, z)            	fprintf(pFp,"%s:= v%d  @kind int @type ^%s;", x, y, toPilar(z))
#define  outSputWide(x, y, z)        	fprintf(pFp,"%s:= v%d  @kind long @type ^%s;", x, y, toPilar(z))
#define  outSputObject(x, y, z)      	fprintf(pFp,"%s:= v%d  @kind object @type ^%s;", x, y, toPilar(z))
#define  outSputBool(x, y, z)        	fprintf(pFp,"%s:= v%d  @kind boolean @type ^%s;", x, y, toPilar(z))
#define  outSputByte(x, y, z)        	fprintf(pFp,"%s:= v%d  @kind byte @type ^%s;", x, y, toPilar(z))
#define  outSputChar(x, y, z)        	fprintf(pFp,"%s:= v%d  @kind char @type ^%s;", x, y, toPilar(z))
#define  outSputShort(x, y, z)       	fprintf(pFp,"%s:= v%d  @kind short @type ^%s;", x, y, toPilar(z))


/********  Note that there are INCONSISTENCIES between above and following macro sets in the context of "z[i]", "y->vB", "y->arg[i], etc"  *****/

char* cut3Char(char* proc)  // not in use now
{
  /* processing a proc name which looks like "[|<name>|]" ; we want to cut it to "name>|]" */
  assert(sizeof(proc) > 7);
  return (&proc[3]);
  /* processing ends;  */
}          


char* cut2Char(char* proc) // not in use now
{
  /* processing a proc name which looks like "[|name|]" ; we want to cut it to "name|]" */
  assert(sizeof(proc) > 5);
  return (&proc[2]);
  /* processing ends;  */
}          

char* cut1Char(char* proc) // in use now
{
  /* processing a proc name which looks like "`name`" ; we want to cut it to "name`" */
  assert(sizeof(proc) > 3);
  return (&proc[1]);
  /* processing ends;  */
}


#define  outInvokeObjectInitRange(x, y, z) { \
  FieldMethodInfo methInfo;\
  if (getMethodInfo(x, y->vB, &methInfo)) { \
    fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
    for (i = 0; i < (int) y->vA; i++) { \
      if (i == 0) \
        fprintf(pFp,"v%u", y->arg[i]);\
      else \
        fprintf(pFp,", v%u", y->arg[i]);\
    }\
    fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind (object, object_init);",methInfo.classDescriptor, methInfo.name,\
      methInfo.signature, descriptorToDot(methInfo.classDescriptor));\
  } \
}


#define  outInvokeVirtual(x, y, z){ \
  FieldMethodInfo methInfo;\
  if (getMethodInfo(x, y->vB, &methInfo)) { \
    fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
    for (i = 0; i < (int) y->vA; i++) { \
      if (i == 0) \
        fprintf(pFp,"v%u", y->arg[i]);\
      else \
        fprintf(pFp,", v%u", y->arg[i]);\
    }\
    fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind virtual;",methInfo.classDescriptor, methInfo.name,\
      methInfo.signature, descriptorToDot(methInfo.classDescriptor));\
  }\
}



#define  outInvokeVirtualQuick(x, y, z) \
    { \
			  fprintf(pFp,"@invoke virtual_quick");\
     }

#define  outInvokeSuper(x, y, z) \
    { \
           FieldMethodInfo methInfo;\
           if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
              for (i = 0; i < (int) y->vA; i++) { \
               if (i == 0) \
                 fprintf(pFp,"v%u", y->arg[i]);\
               else \
                 fprintf(pFp,", v%u", y->arg[i]);\
                    }\
               fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind super;",methInfo.classDescriptor, methInfo.name,\
                   methInfo.signature, descriptorToDot(methInfo.classDescriptor));\
         }\
	}


#define  outInvokeSuperQuick(x, y, z) \
    { \
		fprintf(pFp,"@invoke super_quick");\
	}


#define  outInvokeDirect(x, y, z) \
    { \
           FieldMethodInfo methInfo;\
           if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
              for (i = 0; i < (int) y->vA; i++) { \
               if (i == 0) \
                 fprintf(pFp,"v%u", y->arg[i]);\
               else \
                 fprintf(pFp,", v%u", y->arg[i]);\
                    }\
               fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind direct;",methInfo.classDescriptor, methInfo.name,\
                   methInfo.signature, descriptorToDot(methInfo.classDescriptor));\
         }\
	}


#define  outInvokeStatic(x, y, z) \
    { \
           FieldMethodInfo methInfo;\
           if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
              for (i = 0; i < (int) y->vA; i++) { \
               if (i == 0) \
                 fprintf(pFp,"v%u", y->arg[i]);\
               else \
                 fprintf(pFp,", v%u", y->arg[i]);\
                    }\
               fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind static;",methInfo.classDescriptor, methInfo.name,\
                   methInfo.signature, descriptorToDot(methInfo.classDescriptor));\
         }\
	}
	

	
#define  outInvokeInterface(x, y, z) \
    { \
           FieldMethodInfo methInfo;\
           if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
              for (i = 0; i < (int) y->vA; i++) { \
               if (i == 0) \
                 fprintf(pFp,"v%u", y->arg[i]);\
               else \
                 fprintf(pFp,", v%u", y->arg[i]);\
                    }\
               fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind interface;",methInfo.classDescriptor, methInfo.name,\
                   methInfo.signature, descriptorToDot(methInfo.classDescriptor));\
         }\
	}

#define outInvokeVirtualRange(x, y, z) \
  { \
          FieldMethodInfo methInfo; \
          if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
          for (i = 0; i < (int) y->vA; i++) { \
            if (i == 0) \
                fprintf(pFp,"v%u", y->vC + i); \
            else \
                fprintf(pFp,", v%u", y->vC + i); \
          } \
          fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind virtual;",methInfo.classDescriptor, methInfo.name, \
                           methInfo.signature, descriptorToDot(methInfo.classDescriptor)); \
          } \
  }



#define outInvokeVirtualQuickRange(x, y, z) \
  { \
	fprintf(pFp,"@invoke virtual_quick_range");\
  }



#define outInvokeSuperRange(x, y, z) \
  { \
          FieldMethodInfo methInfo; \
          if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
          for (i = 0; i < (int) y->vA; i++) { \
            if (i == 0) \
                fprintf(pFp,"v%u", y->vC + i); \
            else \
                fprintf(pFp,", v%u", y->vC + i); \
          } \
          fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind super;",methInfo.classDescriptor, methInfo.name, \
                           methInfo.signature, descriptorToDot(methInfo.classDescriptor)); \
          } \
  }



#define outInvokeSuperQuickRange(x, y, z) \
  { \
	fprintf(pFp,"@invoke super_quick_range");\
  }

#define outInvokeDirectRange(x, y, z) \
  { \
          FieldMethodInfo methInfo; \
          if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
          for (i = 0; i < (int) y->vA; i++) { \
            if (i == 0) \
                fprintf(pFp,"v%u", y->vC + i); \
            else \
                fprintf(pFp,", v%u", y->vC + i); \
          } \
          fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind direct;",methInfo.classDescriptor, methInfo.name, \
                           methInfo.signature, descriptorToDot(methInfo.classDescriptor)); \
          } \
  }


#define outInvokeStaticRange(x, y, z) \
  { \
          FieldMethodInfo methInfo; \
          if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
          for (i = 0; i < (int) y->vA; i++) { \
            if (i == 0) \
                fprintf(pFp,"v%u", y->vC + i); \
            else \
                fprintf(pFp,", v%u", y->vC + i); \
          } \
          fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind static;",methInfo.classDescriptor, methInfo.name, \
                           methInfo.signature, descriptorToDot(methInfo.classDescriptor)); \
          } \
  }

#define outInvokeInterfaceRange(x, y, z) \
  { \
          FieldMethodInfo methInfo; \
          if (getMethodInfo(x, y->vB, &methInfo)) { \
              fprintf(pFp,"call temp:=  `%s.%s(", descriptorToDot(methInfo.classDescriptor), cut1Char(z));\
          for (i = 0; i < (int) y->vA; i++) { \
            if (i == 0) \
                fprintf(pFp,"v%u", y->vC + i); \
            else \
                fprintf(pFp,", v%u", y->vC + i); \
          } \
          fprintf(pFp,") @signature `%s.%s:%s` @classDescriptor ^`%s` @kind interface;",methInfo.classDescriptor, methInfo.name, \
                           methInfo.signature, descriptorToDot(methInfo.classDescriptor)); \
          } \
  }



#define  outExecuteInline(x, y, z) \
    { \
		fprintf(pFp,"@invoke execute_inline");\
     }


#define outExecuteInlineRange(x, y, z) \
  { \
	fprintf(pFp,"@invoke execute_inline_range");\
  }


#define          outUnopNegInt(x, y)        fprintf(pFp,"v%d:= -v%d  @kind int;", x, y)
#define          outUnopNotInt(x, y)        fprintf(pFp,"v%d:= ~v%d  @kind int;", x, y)
#define          outUnopNegLong(x, y)       fprintf(pFp,"v%d:= -v%d  @kind long;", x, y)
#define          outUnopNotLong(x, y)       fprintf(pFp,"v%d:= ~v%d  @kind long;", x, y)
#define          outUnopNegFloat(x, y)      fprintf(pFp,"v%d:= -v%d  @kind float;", x, y)
#define          outUnopNegDouble(x, y)     fprintf(pFp,"v%d:= -v%d  @kind double;", x, y)
#define          outUnopInt2Long(x, y)      fprintf(pFp,"v%d:= (long)v%d  @kind i2l;", x, y)
#define          outUnopInt2Float(x, y)     fprintf(pFp,"v%d:= (float)v%d  @kind i2f;", x, y)
#define          outUnopInt2Double(x, y)    fprintf(pFp,"v%d:= (double)v%d  @kind i2d;", x, y)
#define          outUnopLong2Int(x, y)      fprintf(pFp,"v%d:= (int)v%d  @kind l2i;", x, y)
#define          outUnopLong2Float(x, y)    fprintf(pFp,"v%d:= (float)v%d  @kind l2f;", x, y)
#define          outUnopLong2Double(x, y)   fprintf(pFp,"v%d:= (double)v%d  @kind l2d;", x, y)
#define          outUnopFloat2Int(x, y)     fprintf(pFp,"v%d:= (int)v%d  @kind f2i;", x, y)
#define          outUnopFloat2Long(x, y)    fprintf(pFp,"v%d:= (long)v%d  @kind f2l;", x, y)
#define          outUnopFloat2Double(x, y)  fprintf(pFp,"v%d:= (double)v%d  @kind f2d;", x, y)
#define          outUnopDouble2Int(x, y)    fprintf(pFp,"v%d:= (int)v%d  @kind d2i;", x, y)
#define          outUnopDouble2Long(x, y)   fprintf(pFp,"v%d:= (long)v%d  @kind d2l;", x, y)
#define          outUnopDouble2Float(x, y)  fprintf(pFp,"v%d:= (float)v%d  @kind d2f;", x, y)
#define          outUnopInt2Byte(x, y)      fprintf(pFp,"v%d:= (byte)v%d  @kind i2b;", x, y)
#define          outUnopInt2Char(x, y)      fprintf(pFp,"v%d:= (char)v%d  @kind i2c;", x, y)
#define          outUnopInt2short(x, y)     fprintf(pFp,"v%d:= (short)v%d  @kind i2s;", x, y)


#define          outAddInt(x, y, z) fprintf(pFp,"v%d:= v%d + v%d  @kind int;", x, y, z)
#define          outSubInt(x, y, z) fprintf(pFp,"v%d:= v%d - v%d  @kind int;", x, y, z)
#define          outMulInt(x, y, z) fprintf(pFp,"v%d:= v%d * v%d  @kind int;", x, y, z)
#define          outDivInt(x, y, z) fprintf(pFp,"v%d:= v%d / v%d  @kind int;", x, y, z)
#define          outRemInt(x, y, z) fprintf(pFp,"v%d:= v%d %% v%d  @kind int;", x, y, z)
#define          outAndInt(x, y, z) fprintf(pFp,"v%d:= v%d ^& v%d  @kind int;", x, y, z)
#define          outOrInt(x, y, z) fprintf(pFp,"v%d:= v%d ^| v%d  @kind int;", x, y, z)
#define          outXorInt(x, y, z) fprintf(pFp,"v%d:= v%d ^~ v%d  @kind int;", x, y, z)
#define          outShlInt(x, y, z) fprintf(pFp,"v%d:= v%d ^< v%d  @kind int;", x, y, z)
#define          outShrInt(x, y, z) fprintf(pFp,"v%d:= v%d ^> v%d  @kind int;", x, y, z)
#define          outUshrInt(x, y, z) fprintf(pFp,"v%d:= v%d ^>> v%d  @kind int;", x, y, z)
#define          outAddLong(x, y, z) fprintf(pFp,"v%d:= v%d + v%d  @kind long;", x, y, z)
#define          outSubLong(x, y, z)  fprintf(pFp,"v%d:= v%d - v%d  @kind long;", x, y, z)
#define          outMulLong(x, y, z)  fprintf(pFp,"v%d:= v%d * v%d  @kind long;", x, y, z)
#define          outDivLong(x, y, z)  fprintf(pFp,"v%d:= v%d / v%d  @kind long;", x, y, z)
#define          outRemLong(x, y, z)  fprintf(pFp,"v%d:= v%d %% v%d  @kind long;", x, y, z)
#define          outAndLong(x, y, z)  fprintf(pFp,"v%d:= v%d ^& v%d  @kind long;", x, y, z)
#define          outOrLong(x, y, z)  fprintf(pFp,"v%d:= v%d ^| v%d  @kind long;", x, y, z)
#define          outXorLong(x, y, z)  fprintf(pFp,"v%d:= v%d ^~ v%d  @kind long;", x, y, z)
#define          outShlLong(x, y, z)  fprintf(pFp,"v%d:= v%d ^< v%d  @kind long;", x, y, z)
#define          outShrLong(x, y, z)  fprintf(pFp,"v%d:= v%d ^> v%d  @kind long;", x, y, z)
#define          outUshrLong(x, y, z)  fprintf(pFp,"v%d:= v%d ^>> v%d  @kind long;", x, y, z)
#define          outAddFloat(x, y, z)  fprintf(pFp,"v%d:= v%d + v%d  @kind float;", x, y, z)
#define          outSubFloat(x, y, z)   fprintf(pFp,"v%d:= v%d - v%d  @kind float;", x, y, z)
#define          outMulFloat(x, y, z)   fprintf(pFp,"v%d:= v%d * v%d  @kind float;", x, y, z)
#define          outDivFloat(x, y, z)   fprintf(pFp,"v%d:= v%d / v%d  @kind float;", x, y, z)
#define          outRemFloat(x, y, z)   fprintf(pFp,"v%d:= v%d %% v%d  @kind float;", x, y, z)
#define          outAddDouble(x, y, z) fprintf(pFp,"v%d:= v%d + v%d  @kind double;", x, y, z)
#define          outSubDouble(x, y, z) fprintf(pFp,"v%d:= v%d - v%d  @kind double;", x, y, z)
#define          outMulDouble(x, y, z) fprintf(pFp,"v%d:= v%d * v%d  @kind double;", x, y, z)
#define          outDivDouble(x, y, z) fprintf(pFp,"v%d:= v%d / v%d  @kind double;", x, y, z)
#define          outRemDouble(x, y, z) fprintf(pFp,"v%d:= v%d %% v%d  @kind double;", x, y, z)

/*********** Should we pass only two parameters in the following 2 address macros?????? When applicable, should we do casting inside the macro?  *****/

#define          outAddInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d + v%d  @kind int;", x, y, z)
#define          outSubInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d - v%d  @kind int;", x, y, z)
#define          outMulInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d * v%d  @kind int;", x, y, z)
#define          outDivInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d / v%d  @kind int;", x, y, z)
#define          outRemInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d %% v%d  @kind int;", x, y, z)
#define          outAndInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^& v%d  @kind int;", x, y, z)
#define          outOrInt2addr(x, y, z)   fprintf(pFp,"v%d:= v%d ^| v%d  @kind int;", x, y, z)
#define          outXorInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^~ v%d  @kind int;", x, y, z)
#define          outShlInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^< v%d  @kind int;", x, y, z)
#define          outShrInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^> v%d  @kind int;", x, y, z)
#define          outUshrInt2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^>> v%d  @kind int;", x, y, z)
#define          outAddLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d + v%d  @kind long;", x, y, z)
#define          outSubLong2addr(x, y, z) fprintf(pFp,"v%d:= v%d - v%d  @kind long;", x, y, z)
#define          outMulLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d * v%d  @kind long;", x, y, z)
#define          outDivLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d / v%d  @kind long;", x, y, z)
#define          outRemLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d %% v%d  @kind long;", x, y, z)
#define          outAndLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^& v%d  @kind long;", x, y, z)
#define          outOrLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^| v%d  @kind long;", x, y, z)
#define          outXorLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^~ v%d  @kind long;", x, y, z)
#define          outShlLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^< v%d  @kind long;", x, y, z)
#define          outShrLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^> v%d  @kind long;", x, y, z)
#define          outUshrLong2addr(x, y, z)  fprintf(pFp,"v%d:= v%d ^>> v%d  @kind long;", x, y, z)
#define          outAddFloat2addr(x, y, z)  fprintf(pFp,"v%d:= v%d + v%d  @kind float;", x, y, z)
#define          outSubFloat2addr(x, y, z)  fprintf(pFp,"v%d:= v%d - v%d  @kind float;", x, y, z)
#define          outMulFloat2addr(x, y, z)  fprintf(pFp,"v%d:= v%d * v%d  @kind float;", x, y, z)
#define          outDivFloat2addr(x, y, z)  fprintf(pFp,"v%d:= v%d / v%d  @kind float;", x, y, z)
#define          outRemFloat2addr(x, y, z) fprintf(pFp,"v%d:= v%d %% v%d  @kind float;", x, y, z)
#define          outAddDouble2addr(x, y, z) fprintf(pFp,"v%d:= v%d + v%d  @kind double;", x, y, z)
#define          outSubDouble2addr(x, y, z)  fprintf(pFp,"v%d:= v%d - v%d  @kind double;", x, y, z)
#define          outMulDouble2addr(x, y, z)  fprintf(pFp,"v%d:= v%d * v%d  @kind double;", x, y, z)
#define          outDivDouble2addr(x, y, z)  fprintf(pFp,"v%d:= v%d / v%d  @kind double;", x, y, z)
#define          outRemDouble2addr(x, y, z)  fprintf(pFp,"v%d:= v%d %% v%d  @kind double;", x, y, z)

#define          outAddLit16(x, y, z)    fprintf(pFp,"v%d:= v%d + %d  @kind int;",x, y, z)
#define          outSubLit16(x, y, z)    fprintf(pFp,"v%d:= v%d - %d  @kind int;",x, y, z)
#define          outMulLit16(x, y, z)    fprintf(pFp,"v%d:= v%d * %d  @kind int;",x, y, z)
#define          outDivLit16(x, y, z)    fprintf(pFp,"v%d:= v%d / %d  @kind int;",x, y, z)
#define          outRemLit16(x, y, z)    fprintf(pFp,"v%d:= v%d %% %d  @kind int;",x, y, z)
#define          outAndLit16(x, y, z)    fprintf(pFp,"v%d:= v%d ^& %d  @kind int;",x, y, z)
#define          outOrLit16(x, y, z)     fprintf(pFp,"v%d:= v%d ^| %d  @kind int;",x, y, z)
#define          outXorLit16(x, y, z)    fprintf(pFp,"v%d:= v%d ^~ %d  @kind int;",x, y, z)
#define          outAddLit8(x, y, z)     fprintf(pFp,"v%d:= v%d + %d  @kind int;",x, y, z)
#define          outSubLit8(x, y, z)     fprintf(pFp,"v%d:= v%d - %d  @kind int;",x, y, z)
#define          outMulLit8(x, y, z)     fprintf(pFp,"v%d:= v%d * %d  @kind int;",x, y, z)
#define          outDivLit8(x, y, z)     fprintf(pFp,"v%d:= v%d / %d  @kind int;",x, y, z)
#define          outRemLit8(x, y, z)     fprintf(pFp,"v%d:= v%d %% %d  @kind int;",x, y, z)
#define          outAndLit8(x, y, z)     fprintf(pFp,"v%d:= v%d ^& %d  @kind int;",x, y, z)
#define          outOrLit8(x, y, z)      fprintf(pFp,"v%d:= v%d ^| %d  @kind int;",x, y, z)
#define          outXorLit8(x, y, z)     fprintf(pFp,"v%d:= v%d ^~ %d  @kind int;",x, y, z)
#define          outShlLit8(x, y, z)     fprintf(pFp,"v%d:= v%d ^< %d  @kind int;",x, y, z)
#define          outShrLit8(x, y, z)     fprintf(pFp,"v%d:= v%d ^> %d  @kind int;",x, y, z)
#define          outUshrLit8(x, y, z)    fprintf(pFp,"v%d:= v%d ^>> %d  @kind int;",x, y, z)
