select distinct
     'Product:'+R1.EntitlementOwner1+'/'+R1.EntitlementOwner2+'/Resmask:'+R1.EntitlementName as 'Entitlement', 
     case 
        when len(R1.ContactEmail) < 1 then 'Unknown' 
        else left(R1.ContactEmail, charindex('@',R1.ContactEmail)-1)+'@ca.com'  
     end as 'Contact',
     case 
        when right(R1.User_ID,1) = '?' then  'Internal: ' + left(R1.User_ID,charindex('?',R1.User_ID)-1) 
        else 'User: '+ R1.User_ID 
     end as "User ID"              
FROM GITHUB_REVIEW R1 
WHERE R1.Application = 'Mainframe'
order by 1,2,3