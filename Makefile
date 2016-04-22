ALL:swsearchts
swsearchts:swtsmain.c swtsfunction.c
	gcc swtsmain.c swtsfunction.c -o swdvb -g 
clean:
	rm swdvb
