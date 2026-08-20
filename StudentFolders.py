import win32security
import ntsecuritycon as con
import shutil, csv, sys, os


# print(os.getcwd())

# namesFile="ClassList_FOR_2023.csv"
# namesFile="ClassList_ADGIS_2024.csv"
# namesFile="ClassList_AESP_2024.csv"
# namesFile='ClassList_RFW_2024_Sec1.csv'
namesFile='ClassList_TEST.csv'
# path=r'\\seg1.ad.selkirk.ca\Users\GIS'  #ADGIS
# path=r'\\seg1.ad.selkirk.ca\Users\SEG\AESP' #AESP
# path=r'\\seg1.ad.selkirk.ca\Users\SEG\RFW'  #RFW
path=r'\\seg2.ad.selkirk.ca\Users\SEG\FOR'   #FOR

templateFolder="template"

shutil.copytree(templateFolder, os.path.join(path,"template"))


with open(namesFile, 'r', encoding='utf-8-sig') as csvfile:
    # creating a csv reader object
    csv_reader = csv.DictReader(csvfile)

    os.chdir(path)

    for row in csv_reader:
        # print(row)
        studentEmail=row["Email"]
        # # studentEmail=studentEmail.rstrip('\n')
        # folderName=studentEmail[:studentEmail.find('@')]
        studentName=row["Student Name"]
        studentName=studentName.replace("-","").replace(" ","")
        studentName=studentName.split(",")
        folderName=studentName[1].lower()+studentName[0].lower()

        # folderName=row["name"]


        print(f"Building folder for {folderName}")
        
        

        # try:

            

        userx, domain, type = win32security.LookupAccountName ("", studentEmail)
        usery, domain, type = win32security.LookupAccountName ("", "Instructors")

        # print(userx, usery)

        shutil.copytree(templateFolder, folderName)

        sd = win32security.GetFileSecurity(folderName, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()   # instead of dacl = win32security.ACL()

        ace_count = dacl.GetAceCount()
        # print('Ace count:', ace_count)


        for i in range(0, ace_count):
            dacl.DeleteAce(0)


        ace_count = dacl.GetAceCount()
        # print('Ace count:', ace_count)

        # dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, userx)
        # dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, usery)

        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE, con.FILE_ALL_ACCESS, userx)
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE, con.FILE_ALL_ACCESS, usery)

        sd.SetSecurityDescriptorDacl(1, dacl, 0)   # may not be necessary
        win32security.SetFileSecurity(folderName, win32security.DACL_SECURITY_INFORMATION, sd)
        print(folderName + " created 1")
        
        # except:
        #     print(studentEmail + " not found")

        ## to check membership of a group opne cmd prompt and enter
        ##net user /domain username
os.rmdir(os.path.join(path,"template"))



