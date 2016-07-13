# salesforce-to-virustotal

This is a very basic POC of Virustotal to Salesforce integration.

The idea is to send attachments via trigger:

trigger AttachmentTrigger on Attachment (after insert) {
    for (Attachment att: trigger.new){
		    virusTotal.sendChecksum(att.id , EncodingUtil.convertToHex(crypto.generateDigest('SHA256', att.body)), att.BodyLength);
    }
}

TODO: 
Create a way to check back after period of time whether a file scan was completed.

I doubt there there is a way to simply recheck without storing checksums inside custom object.

There are quite a few file size limitations on Salesforce part. 

Alternative path would be creating middleware in Heroku which would fetch attachments.