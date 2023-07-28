from collections import Counter

while True:
    apts=[]
    try:
        with open("allthreats.txt","r") as threat_list:
            for a in threat_list:
                apts.append(a.strip().lower().replace(" ",""))
    except FileNotFoundError:
        print("Please run get_techniques.py first.")
        break

    techniques_list=[]
    sector=input("Enter a sector(such as energy,telecommunications,manufacturing,pharmaceutical,aerospace and (q to quit)): ")
    if sector.lower()=="q":
        print("Quitting...")
        break
        

    with open(f"techniques_{sector.lower()}_sector.txt","r") as techs:
        for t in techs:
            if t.strip().lower().replace(" ","") in apts:
                continue
            else:
                techniques_list.append(t.strip())

    print(f"*****Common techniques related {sector} sector:*****\n")

    techniques_count=Counter(techniques_list)

    for element, count in techniques_count.most_common():
        if(len(element)):
            print(f"{element}: {count}")
    print("\n")
