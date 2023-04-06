# More ergonomic
Ideally we'd only require a single build pass to get everything in place, but since the initramfs is being 
compiled into the kernel that's not possible.  
It could at least be improved though.  
# Maybe make the header bit-rot resistant
Having bit-rot ruin the kernel image isn't a complete disaster but pretty annoying, 
especially if you don't get to know why.  