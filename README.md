#Process Hollowing

Process hollowing is yet another tool in the kit of those who seek to hide the presence of a process. The idea is rather straight forward: a bootstrap application creates a seemingly innocent process in a suspended state. The legitimate image is then unmapped and replaced with the image that is to be hidden. If the preferred image base of the new image does not match that of the old image, the new image must be rebased. Once the new image is loaded in memory the EAX register of the suspended thread is set to the entry point. The process is then resumed and the entry point of the new image is executed.

As Quoted from John Leitch's [PDF](http://www.autosectools.com/process-hollowing.pdf)

#Resources

Process Hollowing Source
http://code.google.com/p/process-hollowing/downloads/list
 
Malware Analyst's Cookbook and DVD: Tools and Techniques for Fighting Malicious Code
http://www.amazon.com/Malware-Analysts-Cookbook-DVD-Techniques/dp/0470613033
 
Microsoft Portable Executable and Common Object File Format Specification
http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/pecoff_v8.docx

Peering Inside the PE: A Tour of the Win32 Portable Executable File Format
http://msdn.microsoft.com/en-us/library/ms809762.aspx

PEB (Process Enviroment Block)
http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PEB.html

/MD, /MT, /LD (Use Run-Time Library)
http://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx

/FIXED (Fixed Base Address)
http://msdn.microsoft.com/en-us/library/w368ysh2(v=vs.80).aspx

/DYNAMICBASE (Use address space layout randomization)
http://msdn.microsoft.com/en-us/library/bb384887.aspx 

C Bit Fields
http://msdn.microsoft.com/en-us/library/yszfawxh(v=vs.80).aspx


#Credits

All Credits for this repository go to John Leitch, for his awesome explanation and sourcecode examples

See Website for more details: http://www.autosectools.com

The Original Code by [John Leitch](http://www.autosectools.com/) is available [here](https://code.google.com/p/process-hollowing/downloads/list)
