import re, traceback, sys
import subprocess
import inspect, os

class checkMemory(object):


  def __init__(self, theFiles, pageSize):
    self.names = []
    self.ids = dict()
    self.results, self.results2 = [],[]
    self.calls , self.calls2 = [],[]
    self.cwd = os.getcwd()
    self.filesPath = "/".join(os.path.abspath(__file__).split("/")[:-1])
    if(not self.cwd == self.filesPath):
      # move files from to cwd from filesPath
      # and save all files in cwd
      name = ["/pageVisual.js","/colours.css","/Memory.html"]
      [subprocess.Popen(["cp",self.filesPath+s,self.cwd+s],stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate() for s in name]
    f = open("memMap2",'w')
    f.close()
    f = open("PageData",'w')
    f.close()
    f = open("PercentPage",'w')
    f.close()
    self.doFiles(theFiles, pageSize)

  # Take each file, open it and compute files for it.
  def doFiles(self, files, pageSize):
    length = len(files)
    for i, theFile in enumerate(files):
      if(i == length-1 and i!=0): # the last file
        self.results = self.results2
        self.computePages(theFile, pageSize)
        break
      if(i==0 and i== length-1):
        self.loopFile(theFile,0,0)
        self.computePages(theFile, pageSize)
        break
      if(i == 0):
        # the next file starts from this position
        pos = self.loopFile(theFile, 0, 0)
      else:
        # this file will be in results2
        self.results = self.results2
        self.results2 = []
        self.calls = self.calls2
        self.calls2 = []
      # get data on next file
      pos = self.loopFile(files[i+1], pos, 1)
      # show the difference between the two files.
      self.diff(theFile, files[i+1])
      # compute the pages for the current file.
      self.computePages(theFile, pageSize)

  # Loops round a file calling finding LKs and
  # returning end point of file.
  def loopFile(self, fileName, pos, toggle):
    print "Opening file %s."%(fileName)
    try:
      f = open(fileName)
      lineNumber = 0
      f.seek(pos)
      for line in f :
        if(toggle == 0):
      	  res = self.results
      	  calls = self.calls
        else:
          res = self.results2
          calls = self.calls2
        # find if LK is on this line
        result = re.search(r'LK', line)
        if(result):
          start = result.start()
          call = ""
          loop= True
          # do this loop while there is LKs in the line
          while(loop):
            loop=False
            index = -1
            if(len(call) == 0):
              callres = re.search(r'^C(\d*\w)',line)
              call = line[callres.start():callres.end()]
              if call.strip() in calls:
                index = calls.index(call.strip())
              else:
                calls.append(call.strip())
            match = line[start:]
            details = match[match.find("("):match.find(")")+1]
            pairs = dict()
            details = details.split(',')
            n1 = details[0].strip().replace("(","")
            n2 = details[1].strip().replace(")","")
            pairs[n1] = n2
            if(lineNumber >= len(res)):
              if(index >= 0):
                res[index]= pairs
                lineNumber = index
              else:
                res.append(pairs)
                lineNumber = len(res)-1
            else:
              res[lineNumber][n1] = n2
            match = match[match.find(")")+1:]
            #if there are more LKs in the line.
            find = re.search(r'LK', match)
            if(find):
              loop = True
              line = match
              start = find.start()
        lineNumber+=1
      # the next file starts from this position
      pos = f.tell()
      f.close()
      return pos
    except IOError:
      traceback.print_exc()
      sys.exit()

  # Shows the differences between files, for each call stack point.
  def diff(self, firstName, secName):
    line = "(%s) %s : %s\n"
    f = open("memMap", 'a')
    f.write("------------------------------------------------------\n")
    for i, x in enumerate(self.calls):
      f.write(line%(firstName,x,str(self.results[i].items()))+'\n')
      if(x in self.calls2):
        inde = self.calls2.index(x)      
        f.write("|\n|\nV\n")
        f.write(line%(secName,x,str(self.results2[i].items()))+'\n\n')
    f.write("------------------------------------------------------\n")
    f.close()
  
  # Addresses are in hex reprsenting bytes, change to dec, 
  # divide by 1024 to get KB. Then divide by pageSize to 
  # get what page number it will be in. If Page size 
  # is  4KB(so 0 to 4095?)if first num before "." is 0 
  # then that's in page0,if its 1 then its in page1 etc
  # e.g. say we have 1025 bytes = 1.00025KB/4 = 0.25 - in page0
  # and 4096/1024 = 4k/4 = 1 - in page 1.
  def computePages(self, name, pageSize):
    pages = []
    # in bytes
    pageStartEnd,mapPageMemStart,mapStartEnd = dict(), dict(), dict()
    for i,x in enumerate(self.results):
      for hexAdd in x:
        decAdd = int(hexAdd, 16) # in bytes
        decKB= float(decAdd)/1024.0 # now in KB
        decVal = int(x[hexAdd],16)
        # this is needed as pageNumber is put into an integer
        # no matter if theres a fraction from the divide.
        # so decKB and addPageStartsAt could end up being different.
        pageNumber = (int(decKB)/pageSize) 
        addPageStartsAt= pageNumber * pageSize # in KB 
        #find if it is spread over more than one page
        endAdd = (decAdd + decVal)-1  # as we store stuff in the firsts
          
        if(endAdd > (addPageStartsAt +pageSize)*1024):
          # the used memory is split over more than one page.
          otherPage = pageNumber + 1
          startsAt = ((addPageStartsAt +pageSize)*1024)
          endsAt = (startsAt + (pageSize*1024)) -1
          if otherPage not in pages:
            pages.append(otherPage)
            pages.sort()
            pageStartEnd[otherPage]= [startsAt,endsAt]
            mapPageMemStart[otherPage]=[startsAt]
          else:
            memUsed = mapPageMemStart[otherPage]
            memUsed.append(startsAt)
            memUsed.sort()
            # not sure if this is needed
            mapPageMemStart[otherPage] = memUsed
          mapStartEnd[startsAt]= endAdd
          # need to set the end add for other pageNumber 
          # - its just the end of its page.
          endAdd = ((addPageStartsAt+pageSize)*1024) -1

        # store
        if pageNumber not in pages:
          pages.append(pageNumber)
          pages.sort()
          pageStartEnd[pageNumber]= [addPageStartsAt*1024,
																((addPageStartsAt+pageSize)*1024)-1]
          mapPageMemStart[pageNumber]=[decAdd]          
        else:
          memUsed = mapPageMemStart[pageNumber]
          memUsed.append(decAdd)
          memUsed.sort()
          # not sure if this is needed
          mapPageMemStart[pageNumber] = memUsed
        mapStartEnd[decAdd]= endAdd
    try:
      # print stuff out
      actualName = name.split("/")[-1]
      print "Creating %s."%("PageMap-"+actualName)
      pageMapFile= open("PageMap-"+actualName, 'w') 
      mapStr= "\tStart: %s. %s bytes long\n\t"\
              "Last byte at: %s. Finishes At: %s\n"  

      pageDataFile = open("PageData",'a')
      pageDataFile.write('\n'+name)
      
      percentFile = open("PercentPage",'a')
      percentFile.write(name+'\n')
      percentStr ="%s,"
      for pageNum in pages:
        hexNum= hex(pageNum)
        # for page map file.
        pageMapFile.write('\nPage number:'+ hexNum)
        startEnd = pageStartEnd[pageNum]
        pageMapFile.write("\nPage starts at:%s \n"%(hex(startEnd[0])))
        previousEnd = startEnd[0]
        totalFree = freePartitions = biggestFree = smallestFree = 0
        #----
        #for page data
        pageDataFile.write("\n%s: "%(hexNum))
        #----
        #for percent file
        percentFile.write(percentStr%(hexNum))
        percent=0
        soFar =0
        full = pageSize*1024.0
        #----
        memStarts = mapPageMemStart[pageNum]
        for start in memStarts:
          #for page data
          actualStart= start - startEnd[0]
          actualEnd = mapStartEnd[start]- startEnd[0] 
          pageDataFile.write("%s - %s,"%(str(actualStart),str(actualEnd)))
          #----
          #for percent file
          soFar += (mapStartEnd[start]- start)+1
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
            pageMapFile.write("Free: %d\n"%(free))
          pageMapFile.write(mapStr%(hex(start),
                           (mapStartEnd[start]- start)+1,
                           hex(mapStartEnd[start]),
				                   hex(mapStartEnd[start]+1)))
          previousEnd = mapStartEnd[start]+1
        endSpace= (startEnd[1] - previousEnd)+1
        if(endSpace>0):
          totalFree += endSpace
          freePartitions +=1
          if(endSpace > biggestFree):
            biggestFree = endSpace
          pageMapFile.write("Free:%d\n" %(endSpace))
        pageMapFile.write("Page ends at: %s\n" %(hex(startEnd[1])))
        pageMapFile.write("Stats: \n\t%d total free in"\
                          " %d partitions.\n"%(totalFree, freePartitions))
        pageMapFile.write("\tBiggest Free: %d."\
				                 " Smallest Free: %d\n"%(biggestFree, smallestFree))
        # percent file
        percent = (soFar/full)*100.0
        percentFile.write(str(int(round(percent))))
        percentStr ="\n%s,"
        #----
      percentFile.write("\n\n")

      percentFile.close()
      pageMapFile.close()
      pageDataFile.close()  
    except IOError:
      traceback.print_exc()
      sys.exit()        

if __name__ == "__main__":
  import optparse, time
  parser = optparse.OptionParser()
  parser.add_option("-f", "--files", dest="_files",
                    help="Argument required. Files to be parsed."\
                         " Can be in format [\"file1\",\"file2\",..]")
  parser.add_option("-p", "--page_size", dest="_page", default=4,
                    help="Default is 4KB. Page size in KB.", type ='int')
  (options, args) = parser.parse_args()
  if not options._files:
    parser.error("No files were supplied.")
  t1 = time.time()
 
  files = options._files.replace("[","").replace("]","")
  if("," in files):
    files = files.split(",")
  else:
    files = files.split(" ")
  print "Files are %s. Page size is %dKB."%(str(files), options._page)
  checkMemory(files, int(options._page))
  t2 = time.time()
  print 'took %0.3f ms' % ((t2-t1)*1000.0)
