import re, traceback, sys
import subprocess
import inspect, os
import gzip
import copy

class checkMemory(object):


  def __init__(self, theFiles, pageSize, doAll, force):
    self.mapPageMemStart,self.mapPageMemStart2 = {},{}
    self.mapStartEnd, self.mapStartEnd2, = {},{}
    self.pageToUsage = {}
    # 0:c1-0
    self.lineToCalls, self.lineToCalls2={},{} 
    # store as c1-0:[(address), address][addrees]
    self.callToAdd,self.callToAdd2 ={},{} 
    self.pageSize,self.forcePage = pageSize, force
    self.pages, self.pages2,self.currentKeys =[],[],[]
    self.percentPage, self.pageMap = "PercentPage","PageMap-"
    self.pageData, self.memMap = "PageData","memMap"
    cwd = os.getcwd()
    filesPath = "/".join(os.path.abspath(__file__).split("/")[:-1])
    if(not cwd == filesPath):
      # move files  to cwd from filesPath
      # and save all files in cwd
      filesPath+="/Memory.html"
      cwd+="/Memory.html"
      subprocess.Popen(["cp",filesPath,cwd],stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate()
    f = open(self.percentPage,'w')
    f.close()
    if(not doAll): # only calculate the PercentPage file.
      for theFile in files:
        self.percentLoop(theFile,0)
        self.printPercentFile(theFile)
    else:
      f = open(self.pageData,'w')
      f.close()
      f = open(self.memMap, 'w')
      f.close()
      theFile = self.doFiles(theFiles)
      if(theFile): # do the diff of last file.
        self.lineToCalls = self.lineToCalls2.copy()
        self.lineToCalls2 ={}
        self.callToAdd = self.callToAdd2.copy()
        self.callToAdd2 ={}
        self.diff(theFile, "")

  # Take each file, open it and compute files for it.
  def doFiles(self, files):
    length = len(files)
    for i, theFile in enumerate(files):
      if(i == length-1 and i!=0): # the last file
        self.printOut(theFile)
        return theFile
      if(i==0): 
        self.loopFile(theFile,0)
        if(i==length-1):# only one file
          self.printOut(theFile)
          self.diff(theFile, "")
          return
      self.loopFile(files[i+1], 1)
      # show the difference between the two files.
      self.diff(theFile, files[i+1])
      # compute the pages for the current file.
      self.printOut(theFile)
      # have done the difference and printed out first file.
      self.lineToCalls = self.lineToCalls2
      self.callToAdd = self.callToAdd2
      self.pages = self.pages2
      self.mapStartEnd = self.mapStartEnd2
      self.mapPageMemStart = self.mapPageMemStart2
      
  # Only calculate what's needed for PercentPage file.
  def percentLoop(self, fileName, toggle):
    print "Opening file %s."%(fileName)
    pageSize = self.pageSize*1024
    memoryMap = {}
    LKRE = re.compile("LK=[(]0x([0-9a-f]+),[ ]*([0-9a-f]+)[)]")
    closeF=0
    zipped = False
    try:  
      if(fileName.endswith(".gz")):
        fi = subprocess.Popen(["zcat",fileName], stdout=subprocess.PIPE)
        na = fileName.split(".")[0]
        # same as normal file, only different loop.
        iterable = iter(fi.stdout.readline,'')
        notFirst = False
        zipped = True
      else:
        iterable = open(fileName, 'r')
        closeF = 1
      # for each line in the file
      for line in iterable:
        if(zipped and na in line and notFirst):
          # start of a new file..
          # finish with this current file
          self.pageToUsage = dict((pageAddr, (size * 100.0) / pageSize) 
             for (pageAddr, size) in memoryMap.items())
          self.pages = [x for x in self.pageToUsage.keys()]
          self.printPercentFile(fileName)
          # now initialise everything and keep looping.  
          memoryMap = {}
        notFirst = True
        if not "LK" in line:
          continue 
        allocs = [(int(x.group(1), 16), int(x.group(2), 16))
                  for x in LKRE.finditer(line)]
        data = [(address, size, address/pageSize, (address+(size-1))/pageSize) 
               for (address, size) in allocs]
        
        # find if LK is on this line
        for address, size, startPage, finalPage in data:
          if startPage == finalPage:
            memoryMap[startPage] = memoryMap.setdefault(startPage,0) + size
            continue
          startSize = pageSize - (address % pageSize)
          endSize = (address + (size)) % pageSize
          memoryMap[startPage] = memoryMap.setdefault(startPage,0) + startSize
          memoryMap[finalPage] = memoryMap.setdefault(finalPage,0) + endSize
          for page in xrange(startPage+1, finalPage-1):
            memoryMap[page] = pageSize
      self.pageToUsage = dict((pageAddr, (size * 100.0) / pageSize) 
             for (pageAddr, size) in memoryMap.items())
      self.pages = [x for x in self.pageToUsage.keys()]
      if(closeF):
        iterable.close()
    except Exception:
      traceback.print_exc()
      sys.exit()

  # Loops round a file finding LKs
  # Stores each LK, so can print out all files.
  def loopFile(self, fileName, toggle):
    print "Opening file %s."%(fileName)
    memoryMapPages, memoryMapSizes = {},{}
    lineToCalls,callToAdd={},{}
    callToNewName ={}
    allCalls=[] # c1, c2
    thelen,closeF = 0,0
    pageSize = self.pageSize*1024
    LKRE = re.compile("LK=[(]0x([0-9a-f]+),[ ]*([0-9a-f]+)[)]")
    CRE = re.compile(r'C(\d*\w)')
    firstDone,secndDone, zipped = False, False, False
    try:
      if(fileName.endswith(".gz")):
        fi = subprocess.Popen(["zcat",fileName], stdout=subprocess.PIPE)
        na = fileName.split(".")[0]
        # same as normal file, only different loop.
        iterable = iter(fi.stdout.readline,'')
        zipped = True
      else:
        iterable = open(fileName, 'r')
        closeF = 1
      # for each line in the file
      for line in iterable :  
        # find if LK is on this line
        if(zipped and na in line):
          # start of a new file..
          # finish with this current file
          if(firstDone):
            # the first one is done, so now we're onto the 2nd.
            # set 2nd done
            self.lineToCalls = lineToCalls
            self.callToAdd = callToAdd
            self.mapStartEnd = memoryMapSizes
            self.mapPageMemStart = memoryMapPages 
            self.pages = [x for x in memoryMapPages.keys()]
            secndDone = True
            firstDone = False
          elif(secndDone):
            # 2nd is done, so we can compare things 
            self.lineToCalls2 = lineToCalls 
            self.callToAdd2 = callToAdd 
            self.mapStartEnd2 = memoryMapSizes
            self.mapPageMemStart2 = memoryMapPages
            self.temp2 = memoryMapPages
            self.pages2 = [x for x in memoryMapPages.keys()]
            # now do diff depending on what we need to do. 
            # If we have things waiting on us or not.
            self.diff(fileName, fileName)
            # compute the pages for the current file.
            self.printOut(fileName)
            # have done the difference and printed out first file.
            self.lineToCalls = self.lineToCalls2
            self.callToAdd = self.callToAdd2
            self.pages = self.pages2
            self.mapStartEnd = self.mapStartEnd2
            self.mapPageMemStart = self.mapPageMemStart2
          else:
            # nothing has been done yet, so its the first
            firstDone = True
          # now initialise everything and keep looping.  
          memoryMapPages, memoryMapSizes = {},{}
          lineToCalls,callToAdd={} ,{}
          callToNewName ={}
          allCalls=[] # c1, c2
        if ("LK" not in line):
          continue
        callres = CRE.search(line) 
        call = line[callres.start(): callres.end()]
        allocs = [(int(x.group(1), 16), int(x.group(2), 16)) 
                  for x in LKRE.finditer(line)]
        data = [(address, size, address/pageSize, (address+(size-1))/pageSize)
                for (address, size) in allocs]
        thelen+=1
        addr = [[address for address in allocs]]
        if(call in allCalls):
          # this call name has already appeared in this file.
          # add these addresses to previous call entry.
          oldName = callToNewName[call]
          callToAdd[oldName].append(addr)
          # added as test
          newName = "%s-%s"%(call,str(thelen))
          callToAdd[newName] = addr[:]
          callToNewName[call] = newName
          lineToCalls[thelen]= newName
          
        else:
          # first time seeing this call entry, or first after match
          # save the call name, make the new name and add addresses.
          allCalls.append(call)
          newName = "%s-%s"%(call,str(thelen))
          callToAdd[newName] = addr[:]
          callToNewName[call] = newName
          lineToCalls[thelen]= newName

        for (address, size, startPage, finalPage) in data:
            memoryMapPages.setdefault(startPage,[]).append(address)
            if startPage == finalPage:
              # need to store how much is stored from that address 
              memoryMapSizes[address]= memoryMapSizes.setdefault(
                                       address,0)+size
              continue
            startSize = pageSize - (address % pageSize)
            endSize = (address + (size)) % pageSize
            add = finalPage*pageSize
            memoryMapSizes[address]= memoryMapSizes.setdefault(
                                      address,0)+ startSize
            memoryMapPages.setdefault(finalPage,[]).append(add)
            memoryMapSizes[add]= memoryMapSizes.setdefault(add,0)+ endSize
            for page in xrange(startPage+1, finalPage-1):
              add = page*pageSize
              memoryMapPages.setdefault(page,[]).append(add)
              memoryMapSizes[add]= memoryMapSizes.setdefault(add,0)+ pageSize

      if(secndDone):
        # 2nd is done, so we can compare things 
        self.lineToCalls2 = lineToCalls 
        self.callToAdd2 = callToAdd 
        self.mapStartEnd2 = memoryMapSizes
        self.mapPageMemStart2 = memoryMapPages
        self.temp2 = memoryMapPages
        self.pages2 = [x for x in memoryMapPages.keys()]
        # now do diff depending on what we need to do.
        # If we have things waiting on us or not.
        self.diff(fileName, fileName)
        # compute the pages for the current file.
        self.printOut(fileName)
        # have done the difference and printed out first file.
        self.lineToCalls = self.lineToCalls2
        self.callToAdd = self.callToAdd2
        self.pages = self.pages2
        self.mapStartEnd = self.mapStartEnd2
        self.mapPageMemStart = self.mapPageMemStart2

      if(toggle == 0):
        self.lineToCalls = lineToCalls.copy()
        self.callToAdd = callToAdd.copy()
        self.mapStartEnd = memoryMapSizes.copy()
        self.mapPageMemStart = memoryMapPages.copy() 
        self.pages = [x for x in memoryMapPages.keys()]
      else:
        self.lineToCalls2 = lineToCalls .copy()
        self.callToAdd2 = callToAdd .copy()
        self.mapStartEnd2 = memoryMapSizes.copy()
        self.mapPageMemStart2 = memoryMapPages.copy()
        self.temp2 = memoryMapPages.copy()
        self.pages2 = [x for x in memoryMapPages.keys()]

      # the next file starts from this position
      if(closeF):
        iterable.close()
    except IOError:
      traceback.print_exc()
      sys.exit()
    
  # Prints out the match up of call stack names
  # Showing the memory usage progression.
  def diff(self, firstName, secName):
    line = "(%s) %s : %s\n\n"
    bufferLine = "|\n|\nV\n"
    fileKeys, otherFileKeys = self.lineToCalls.keys(),self.lineToCalls2.keys()
    fileKeys.sort()
    otherFileKeys.sort()
    currentKeys = otherFileKeys
    try:
      print "Writing to memMap file."
      f = open(self.memMap, 'a')
      f.write("----------------------------------\n")
      for lineNumber in fileKeys: 
        fullName = self.lineToCalls[lineNumber]
        callName = fullName.split("-")[0]
        addr = self.callToAdd[fullName]
        f.write(line%(firstName,callName,str(addr[0])))
        if(len(addr)>1):
          # then we found the matching one in the same file.
          f.write(bufferLine)
          f.write(line%(firstName,callName,str(addr[1])))
          continue
        # see if its in the other file.
        for lineNumber2 in otherFileKeys: #otherFileKeys
          fullName = self.lineToCalls2[lineNumber2]
          if(fullName.split("-")[0] == callName):
            # we found a match - print it out
            addr = self.callToAdd2[fullName]
            f.write(bufferLine)
            f.write(line%(secName,callName,str(addr[0])))
            currentKeys.remove(lineNumber2)
            break
        otherFileKeys = currentKeys
      # instead save the stuff from 2nd file in first parts
      self.currentKeys = otherFileKeys
      f.close()
    except IOError:
      traceback.print_exc()
      sys.exit()

  #Only prints the percent file.
  def printPercentFile(self, name):
    print "printing only percent file - %s"%(self.percentPage)
    self.pages.sort()
    print "sorted pages"
    percentStr ="%s,"
    pageSize = self.pageSize
    print "number of pages "+ str(len(self.pages))
    answer = len(self.pages)/(pageSize*1024)
    try:
      percentFile = open(self.percentPage,'a')
      percentFile.write(name+'\n')
      if(answer >0 and not self.forcePage):
        # if we can choose the page size and the current one isn't big enough.
        newOne = pageSize+(answer*4)
        percentFile.write("%s\n"%(str(newOne)))
        # So we want to find the new page numbers
        waiting =0
        waitingPercent = 0
        divide = (newOne/pageSize)
        
        for pageNum in self.pages:
          newOne = pageNum/divide
          if(waiting >0):
            if(newOne == waiting):
              waitingPercent += self.pageToUsage[pageNum]
              continue
            else:
              percentFile.write(percentStr%(hex(waiting)))
              percent = waitingPercent/divide
              if(percent < 1):
                percent+=0.5
              percentFile.write(str(int(round(percent))))
              percentStr ="\n%s,"
          waiting = newOne
          waitingPercent = self.pageToUsage[pageNum]
        percentFile.write(percentStr%(hex(waiting)))
        percent = waitingPercent/divide
        if(percent < 1):
          percent+=0.5
        percentFile.write(str(int(round(percent))))
      
      else:
        percentFile.write(str(pageSize)+'\n')
        for pageNumber in self.pages:
          # percent file
          percentFile.write(percentStr%(hex(pageNumber)))
          percent = (self.pageToUsage[pageNumber])
          if(percent < 1):
            percent+=0.5
          percentFile.write(str(int(round(percent))))
          percentStr ="\n%s,"
      
    except IOError:
      traceback.print_exc()
      sys.exit()
    else:
      percentFile.write("\n\n")
      percentFile.close()

  # Prints out all files.
  def printOut(self, name):
    pages = self.pages
    pageMemStart = self.mapPageMemStart
    startEnd = self.mapStartEnd
    test = pageMemStart
    for key, li in pageMemStart.items():
      test[key] = list(set(li))
    pageMemStart = test
    pages.sort()
    pS = self.pageSize
    pageSize = self.pageSize*1024
    actualName = name.split("/")[-1]
    answer = len(pages)/(pageSize)
    try:
      # print stuff out
      print "Creating %s, %s, %s."%(self.pageMap+actualName, 
                                    self.pageData, self.percentPage)
      pageMapFile= open(self.pageMap+actualName, 'w') 
      pageDataFile = open(self.pageData,'a')
      pageDataFile.write("\n%s"%(name))
      percentFile = open(self.percentPage,'a')
      percentFile.write("%s\n"%(name))
      if(answer >0 and not self.forcePage):
        newPageSize = pS+(answer*4) # in kb
        percentFile.write("%s\n"%(str(newPageSize)))
        self.calcPagePrintAll(newPageSize,percentFile,pageDataFile,pageMapFile)
      else:
        mapStr= "\tStart: %s. %s bytes long\n\t"\
              "Last byte at: %s. Finishes At: %s\n"
        freeStr= "Free: %d\n"
        bFreeStr= "\tBiggest Free: %d. Smallest Free: %d\n"
        sStr = "Stats: \n\t%d total free in %d partitions.\n"
        pEndsStr= "Page ends at: %s\n"
        dataStr= "%s - %s,"
        percentStr ="%s,"
        pNStr= "\nPage number:%s"
        startsStr= "\nPage starts at:%s \n"
        percentFile.write("%s\n"%(str(pS)))
        for pageNum in self.pages:
          hexNum= hex(pageNum)
          # for page map file.
          pageMapFile.write(pNStr%(hexNum))
          startAdd = pageNum*pageSize # the address the page starts at
          endAdd = startAdd + (pageSize-1) # minus 1?
          pageMapFile.write(startsStr%(hex(startAdd)))
          previousEnd = startAdd
          totalFree = freePartitions = biggestFree = smallestFree = 0
          #----
          #for page data
          pageDataFile.write("\n%s: "%(hexNum))
          #----
          #for percent file
          percentFile.write(percentStr%(hexNum))
          percent=soFar=0
          full = self.pageSize*1024.0
          #----
          memStarts = pageMemStart[pageNum]
          memStarts.sort()
          for start in memStarts:
            #for page data
            actualStart= start - startAdd 
            # the address where the mem starts at minus 
            #the address the page starts at
            size = startEnd[start] # this should just give how much is used now
            actualEnd = actualStart+ size
            pageDataFile.write(dataStr%(str(actualStart),str(actualEnd)))
            #----
            #for percent file
            # so far keeps track of how much is used
            soFar +=size
            #----
            # rest of loop for page map file
            free = start - previousEnd
            if(free >0):
              if(biggestFree ==0):
                smallestFree = free
              if(free > biggestFree):
                biggestFree = free
              if(free < smallestFree):
                smallestFree = free
              totalFree += free
              freePartitions +=1
              pageMapFile.write(freeStr%(free))
            pageMapFile.write(mapStr%(hex(start),
                           size,
                           hex(start+size-1),
                           hex(start+size)))
            previousEnd =start+size
          endSpace= (endAdd - previousEnd)+1
          if(endSpace>0):
            totalFree += endSpace
            freePartitions +=1
            if(endSpace > biggestFree):
              biggestFree = endSpace
            pageMapFile.write(freeStr %(endSpace))
          pageMapFile.write(pEndsStr %(hex(endAdd)))
          pageMapFile.write(sStr%(totalFree, freePartitions))
          pageMapFile.write(bFreeStr%(biggestFree, smallestFree))
          # percent file
          percent = (soFar/full)*100.0
          if(percent < 1):
            percent+=0.5
          percentFile.write(str(int(round(percent))))
          percentStr ="\n%s,"
          #----
        
    except IOError:
      # can put these here as the files will always be found.
      percentFile.close()
      pageMapFile.close()
      pageDataFile.close() 
      traceback.print_exc()
      sys.exit()
    else:
      percentFile.write("\n\n")
      percentFile.close()
      pageMapFile.close()
      pageDataFile.close() 
    
  # Calculates an appropiate page size, prints out all files.
  def calcPagePrintAll(self,newPageSize,percentFile,pageDataFile,pageMapFile):
    print "new page sizes"
    pages = self.pages
    mapStr= "\tStart: %s. %s bytes long\n\t"\
              "Last byte at: %s. Finishes At: %s\n"
    percentStr ="%s,"
    # now need to be able to change everything to be new pages
    # just keep the strings or keep data?
    waitingNumber,waitingSize = 0, 0
    full = newPageSize*1024.0
    newPageSizeB=  int(full)
    newPageSizeBL=  int(full-1)
    divide = (newPageSize/self.pageSize)
    startAdd = totalFree = freePartitions = biggestFree = smallestFree = 0
    previousEnd = startAdd
    freeStr= "Free: %d\n"
    bFreeStr= "\tBiggest Free: %d. Smallest Free: %d\n"
    sStr = "Stats: \n\t%d total free in %d partitions.\n"
    pEndsStr= "Page ends at: %s\n"
    dataStr= "%s - %s,"
    pNStr= "\nPage number:%s"
    startsStr= "\nPage starts at:%s \n"
    for pageNum in pages:
      newPageNumber = pageNum/divide # new pageNumber
      startAdd = newPageNumber*newPageSizeB# the address the page starts at
      memStarts = self.mapPageMemStart[pageNum]
      memStarts.sort()
      if(waitingNumber >0):
        if(newPageNumber == waitingNumber):
          # just add to the waiting stuff, can print out pageData
          for start in memStarts:
            size = self.mapStartEnd[start]
            waitingSize += size
            # now for pageData
            actualStart= start - startAdd 
            # the address where the mem starts at minus 
            # the address the page starts at
            pageDataFile.write(dataStr%(str(actualStart),
                              str(actualStart+ size))) # okay to print it out
            #----
       			# rest of loop for page map file
            # can store the previous end
            free = start - previousEnd
            if(free >0):
              if(biggestFree ==0):
                smallestFree = free
              if(free > biggestFree):
                biggestFree = free
              if(free < smallestFree):
                smallestFree = free
              totalFree += free
              freePartitions +=1
              pageMapFile.write(freeStr%(free))
            previousEnd = start+size
            pageMapFile.write(mapStr%(hex(start), size, hex(previousEnd-1),
                              hex(previousEnd)))
          continue 
        else:
         # Write waiting data to percent file.
         percentFile.write(percentStr%(hex(waitingNumber)))
         percent = (waitingSize/full)*100.0
         if(percent < 1):
           percent+=0.5
         percentFile.write(str(int(round(percent))))
         percentStr ="\n%s,"
        # PageData doesn't need anything else
        # PageMap does though
        # need to write the end -
        # so whats free, where the page ends and the stats
        endSpace= (endAdd - previousEnd)+1
        if(endSpace>0):
          totalFree += endSpace
          freePartitions +=1
          if(endSpace > biggestFree):
            biggestFree = endSpace
          pageMapFile.write(freeStr %(endSpace))
        pageMapFile.write(pEndsStr %(hex(endAdd)))
        pageMapFile.write(sStr%(totalFree, freePartitions))
        pageMapFile.write(bFreeStr%(biggestFree, smallestFree))
        previousEnd = startAdd
        totalFree = freePartitions = biggestFree = smallestFree = 0
        # still need to store the current page stuff.. fall to after if.

      # after if
      # it's 0, so first one, just store, can print some stuff.
      #store things for percent file.
      waitingNumber = newPageNumber
      waitingSize = 0
      hexNewPage = hex(newPageNumber)
      # print for pageMapFile
      pageMapFile.write(pNStr%(hexNewPage))
      pageMapFile.write(startsStr%(hex(startAdd)))
      # print pageData file
      pageDataFile.write("\n%s: "%(hexNewPage))
      endAdd = startAdd + newPageSizeBL # minus 1?
      previousEnd = startAdd
      for start in memStarts:
        size = self.mapStartEnd[start]
        waitingSize += size
        # now for pageData
        actualStart= start - startAdd 
        # the address where the mem starts at minus the address 
        # the page starts at
        pageDataFile.write(dataStr%(str(actualStart),str(actualStart + size))) 
        # okay to print it out?
        #----
      	# rest of loop for page map file
        # can store the previous end
        free = start - previousEnd
        if(free >0):
          if(biggestFree ==0):
             smallestFree = free
          if(free > biggestFree):
            biggestFree = free
          if(free < smallestFree):
            smallestFree = free
          totalFree += free
          freePartitions +=1
          pageMapFile.write(freeStr%(free))
        previousEnd = start+size
        pageMapFile.write(mapStr%(hex(start), size,
                         hex(previousEnd-1), hex(previousEnd)))
    #need to check for things left over!
    # so write last pecernt things
    percentFile.write(percentStr%(hex(waitingNumber)))
    percent = (waitingSize/full)*100.0
    if(percent < 1):
      percent+=0.5
    percentFile.write(str(int(round(percent))))
    percentStr ="\n%s,"
    #write last pageMap
    endSpace= (endAdd - previousEnd)+1
    if(endSpace>0):
      totalFree += endSpace
      freePartitions +=1
      if(endSpace > biggestFree):
        biggestFree = endSpace
      pageMapFile.write(freeStr %(endSpace))
    pageMapFile.write(pEndsStr %(hex(endAdd)))
    pageMapFile.write(sStr%(totalFree, freePartitions))
    pageMapFile.write(bFreeStr%(biggestFree, smallestFree))
    return

      
if __name__ == "__main__":
  import optparse, time, profile
  parser = optparse.OptionParser()
  flags =["-p","-e","-P"]
  parser.add_option("-f", "--files", dest="_files",
                    help="Argument required. Files to be parsed."\
                         " Can be in format [\"file1\",\"file2\",..]")
  parser.add_option("-p", "--page_size", dest="_page", default=4,
                    help="Default is 4KB. Page size in KB. "\
                    "This will just be a guide."\
                    " To force this size use -P.", type ='int')
  parser.add_option("-e", "--compute_all", dest="_all", default=False,
                    action="store_true",
                    help="Compute all pages. Default is False"\
                    " - only computes pages needed for visualiser.")
  parser.add_option("-P", "--force_page", dest="_force", default=False,
                    action="store_true",
                    help="Force the page size to be adhered to.")
  (options, args) = parser.parse_args()
  print "options "+ str(options)
  if not options._files:
    err = False
    if(len(sys.argv)==1):
      err = True
    else:
      files = sys.argv[1:]
      for x in flags:
        if(x in files):
          inde = files.index(x)
          del files[inde: inde+2]
          if(len(files)==0):
            err = True
    if(err):
      parser.error("No files were supplied.")  
  else:
    files = [options._files.replace("[","").replace("]","")]
    if(" " in files):
      files = files.split(",")

  print "Files are %s. Page size is %dKB."%(str(files), options._page)
  t1 = time.time()
  checkMemory(files, int(options._page), options._all, options._force)
  t2 = time.time()
  print 'took %0.3f ms' % ((t2-t1)*1000.0)
