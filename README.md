#Process Hollowing
Process hollowing is yet another tool in the kit of those who seek to hide the presence of a process. The idea is rather straight forward: a bootstrap application creates a seemingly innocent process in a suspended state. The legitimate image is then unmapped and replaced with the image that is to be hidden. If the preferred image base of the new image does not match that of the old image, the new image must be rebased. Once the new image is loaded in memory the EAX register of the suspended thread is set to the entry point. The process is then resumed and the entry point of the new image is executed.

The Original Code by [John Leitch](http://www.autosectools.com/) is available [here](https://code.google.com/p/process-hollowing/downloads/list)

All Credits to:

John Leitch
john@autosectools.com
http://www.autosectools.com/
