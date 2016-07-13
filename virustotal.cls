public class virustotal {
    private static Virustotal__c[] settings = Virustotal__c.getall().values();
   
    
    @future (callout=true)
    public static void sendChecksum(id recordId, string checksum, integer BodyLength) { //test sum 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
        if ( !settings.isEmpty()){
            HttpRequest req = new HttpRequest();
            HttpResponse res = new HttpResponse();
            Http http = new Http();
            req.setEndpoint('https://www.virustotal.com/vtapi/v2/file/rescan');
            req.setMethod('POST');
            req.setBody('resource='+ checksum +'&apikey='+settings[0].API_Key__c);
            req.setCompressed(true);
            try {
                res = http.send(req);
                system.debug(res);
                if (parse(res.getBody()).response_code == 1){
                    getReport(recordId, checksum);
                } else {
                    if ( ! settings[0].Submit_only_checksums__c && BodyLength < 6000000){
                        // put filename validations
                        sendFile(recordId);
                        getReport(recordId, checksum); // need to put this into batch
                    }
                }
            } catch(System.CalloutException e) {
                System.debug('Callout error: '+ e);
                System.debug(res.toString());
            }
        }
    }

    public static void getReport(id recordId, string checksum) {
        if ( !settings.isEmpty()){
            HttpRequest req = new HttpRequest();
            HttpResponse res = new HttpResponse();
            Http http = new Http();
            
            req.setEndpoint('https://www.virustotal.com/vtapi/v2/file/report');
            req.setMethod('POST');
            req.setBody('resource='+ checksum +'&apikey='+settings[0].API_Key__c);
            req.setCompressed(true);
            try {
                res = http.send(req);
                string jsonResponse = res.getBody();
                
                Map<String,Object> data  = (Map<String,Object>)JSON.deserializeUntyped(jsonResponse);
                
                system.debug(data);
                double totalScans = (double)data.get('total');
                system.debug('totalScans ' + totalScans);
                if ( totalScans == null){


                        getReport(recordId, checksum);

                } else {
                    double positiveDetections = (double)data.get('positives');
                    double detectionRate = positiveDetections /totalScans ;
                    if ( detectionRate > 0)
                        handleDetection (recordId, detectionRate);
                }
            } catch(System.CalloutException e) {
                System.debug('Callout error: '+ e);
                System.debug(res.toString());
            }
        }
    }
    @FUTURE
    public static void getReport2(id recordId, string checksum) {}
    private static void sendFile(string attId){
        if ( !settings.isEmpty()){
            attachment attachmentToUpload = [select body, name from attachment where id=: attId];
            String boundary = '----------------------------741e90d31eff';
            string header1 = '--'+boundary+'\nContent-Disposition: form-data; name="apikey" \r\n\r\n'+settings[0].API_Key__c;
            String header =  header1+'\n'+'--'+boundary+'\nContent-Disposition: form-data; name="file"; filename="'+attachmentToUpload.name+'";\nContent-Type: application/octet-stream';
            String footer = '--'+boundary+'--';             
            String headerEncoded = EncodingUtil.base64Encode(Blob.valueOf(header+'\r\n\r\n'));
            while(headerEncoded.endsWith('='))
            {
                header+=' ';
                headerEncoded = EncodingUtil.base64Encode(Blob.valueOf(header+'\r\n\r\n'));
            }
            String bodyEncoded = EncodingUtil.base64Encode(attachmentToUpload.body);
            Blob bodyBlob = null;
            String last4Bytes = bodyEncoded.substring(bodyEncoded.length()-4,bodyEncoded.length());
            
            if(last4Bytes.endsWith('==')) {
                
                last4Bytes = last4Bytes.substring(0,2) + '0K';
                bodyEncoded = bodyEncoded.substring(0,bodyEncoded.length()-4) + last4Bytes;
                
                String footerEncoded = EncodingUtil.base64Encode(Blob.valueOf(footer));
                bodyBlob = EncodingUtil.base64Decode(headerEncoded+bodyEncoded+footerEncoded);
            } else if(last4Bytes.endsWith('=')) {
                
                last4Bytes = last4Bytes.substring(0,3) + 'N';
                bodyEncoded = bodyEncoded.substring(0,bodyEncoded.length()-4) + last4Bytes;
                footer = '\n' + footer;
                String footerEncoded = EncodingUtil.base64Encode(Blob.valueOf(footer));
                bodyBlob = EncodingUtil.base64Decode(headerEncoded+bodyEncoded+footerEncoded);              
            } else {
                footer = '\r\n' + footer;
                String footerEncoded = EncodingUtil.base64Encode(Blob.valueOf(footer));
                bodyBlob = EncodingUtil.base64Decode(headerEncoded+bodyEncoded+footerEncoded);  
            }
            
            HttpRequest req = new HttpRequest();
            req.setHeader('Content-Type','multipart/form-data; boundary='+boundary);
            req.setMethod('POST');
            //req.setbody ( bodyblob.toString() );
            req.setBodyAsBlob(bodyblob);
            req.setEndpoint('https://www.virustotal.com/vtapi/v2/file/scan');
            
            req.setTimeout(120000);
            
            Http http = new Http();
            HTTPResponse res = http.send(req);
            // parse response - looks if report is live, then pull it
            // else wait?
            //system.debug (res.getBody());
        }
    }
    
    public static void handleDetection(string attId, double detectionPercentage){
        // get the variables
        
        boolean notifyOwner = true; // set default to true
        boolean notifySysadmin = true;
        double deleteThreshold = 0.1;
        double markThreshold = 0.01;
        
        if (! settings.isEmpty() ){
            notifyOwner 	= settings[0].Notify_Owner__c;
            notifySysadmin 	= settings[0].Notify_System_Administrators__c;
            deleteThreshold = settings[0].Delete_Threshold__c;
            markThreshold 	= settings[0].Detection__c;
        }
        user[] sysAdmins = [select id, email from user where isactive = true and profile.name = 'System administrator'];
        attachment detectedFile = [select id, name, ownerId, isprivate, owner.email, owner.name from attachment where id =: attId];
        List<Messaging.SingleEmailMessage> mails = new List<Messaging.SingleEmailMessage>();
        if ( detectionPercentage > markThreshold && !sysAdmins.isEmpty() ){
            // set owner as sysadmin and set file to private
            detectedFile.ownerid = sysAdmins[0].id;
            detectedFile.IsPrivate = true;
            update detectedFile;
        }
        if ( detectionPercentage > deleteThreshold ){
            delete detectedFile;
        }
        if ( detectionPercentage > 0 && notifyOwner){// notify owner
            Messaging.SingleEmailMessage mail = new Messaging.SingleEmailMessage();
            string[] ownerEmails = new string[]{detectedFile.owner.email};
                mail.setToAddresses(ownerEmails); 
            mail.setSenderDisplayName('VirusTotal Detection Handler');
            mail.setSubject('Detection detected on file '+ detectedFile.name);
            String body = 'Detection of '+ detectionPercentage*100+ '% found on file '
                + detectedFile.name + '. File id: '+ detectedFile.id;
            mail.setHtmlBody(body);
            mails.add(mail);
        }
        if ( detectionPercentage > 0 && notifySysadmin && ! sysAdmins.isEmpty()){ // notify sysadmin
            Messaging.SingleEmailMessage mail = new Messaging.SingleEmailMessage();
            string[] sysAdminMails = new string[]{};
            for ( user u: sysAdmins)
                sysAdminMails.add(u.email);
                
            mail.setToAddresses(sysAdminMails);
            mail.setSenderDisplayName('VirusTotal Detection Handler');
            mail.setSubject('Detection detected on file '+ detectedFile.name);
            String body = 'Detection of '+ detectionPercentage*100+ '% found on file '
                + detectedFile.name + '. File id: '+ detectedFile.id +'\n\n File belongs to: '+
                detectedFile.owner.name;
            mail.setHtmlBody(body);
            mails.add(mail);
        }
        if (! mails.isEmpty())
            messaging.sendEmail(mails);
    }
    
    private String permalink;
    private Integer response_code;
    private String sha256;
    private String resource;
    private String scan_id;
    
    
    private static virustotal parse(String json) {
        return (virustotal) System.JSON.deserialize(json, virustotal.class);
    }
}