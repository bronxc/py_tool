'''
format the chronic raw poc by try_catch
'''
import os
import sys

def determine(raw_text):
    b_pos = raw_text.find("try")
    while (b_pos>0):
        print b_pos
        result = partition_func(raw_text,b_pos,len("try"),len(" catch(err){}"))
        raw_text = result[0]
        e_pos = result[1]
        b_pos = raw_text.find("try",e_pos)
        
    #b_pos = raw_text.find("function")
    #while (b_pos>0):
    #    print b_pos
    #    raw_text = partition_func(raw_text,b_pos,len("function function_1905()"))
    #    b_pos = raw_text.find("try",b_pos+len("function function_1905()"))
    return raw_text
    
def partition_func(raw_text,pos,wildcard,padding=0):
    stack = 0
    start = pos + wildcard 
    for x in range(start,len(raw_text)):
        if raw_text[x] == '{':
            stack+=1
        if raw_text[x] == '}':
            stack-=1
            if stack == 0 :
                break
    start = start +1
    end = x + 1 + padding
    raw_text = raw_text[0:start] + "\n" + raw_text[start:end]  + "\n" +raw_text[end:]
    return [raw_text,end]
    
    
if __name__=="__main__":
    src_file = open(sys.argv[1])
    raw_text = src_file.read()
    dst_file = open(sys.argv[1][:-5]+"_org.html","wb")
    dst_file.write(raw_text)
    src_file.close()
    dst_file.close()
    raw_text = determine(raw_text)
    dst_file = open(sys.argv[1],"wb")
    dst_file.write(raw_text)

