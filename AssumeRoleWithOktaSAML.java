import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HTTP;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult;
import com.amazonaws.auth.*;

public class AssumeRoleWithOktaSAML {

	public static void main(String[] args) throws Exception {
		
		//check if credentials file has been created
		File f = new File (System.getProperty("user.home")+"/.aws/credentials");
		if(!f.exists()){
			f.getParentFile().mkdirs();
			
			PrintWriter writer = new PrintWriter(f, "UTF-8");
			writer.println("[default]");
			writer.println("aws_access_key_id=");
			writer.println("aws_secret_access_key=");
			writer.close();
		}
		
		//User specific variables
		String oktaOrg = "";
		String oktaAWSAppURL = "";
		String oktaUsername;
		String oktaPassword;
		
		BufferedReader oktaBr = new BufferedReader(new FileReader(new File (System.getProperty("user.dir")) +"/oktaAWSCLI.config"));
		
		//extract oktaOrg and oktaAWSAppURL from Okta settings file
		String line = oktaBr.readLine();
		while(line!=null){
			if(line.contains("OKTA_ORG")){
				oktaOrg = line.substring(line.indexOf("=")+1).trim();
			}
			else if( line.contains("OKTA_AWS_APP_URL")){
				oktaAWSAppURL = line.substring(line.indexOf("=")+1).trim();
			}
			line = oktaBr.readLine();
		}	
		oktaBr.close();
		
		// Part 1: Initiate the authentication and capture the SAML assertion.
		Scanner scanner = new Scanner(System.in);	
		CloseableHttpClient httpClient = null;
		CloseableHttpResponse responseAuthenticate = null;
		CloseableHttpResponse responseSAML = null;
		HttpPost httpost = null;
		HttpGet httpget = null;
		String resultSAML = "";
		int requestStatus = 0;

		try {		
			//Redo sequence if response from AWS doesn't return 200 Status
			while(requestStatus != 200){
				
		 		// Prompt for user credentials
		 		System.out.print("Username: ");
		 		oktaUsername = scanner.next();
		 		
		 		Console console = System.console();
		 		oktaPassword = new String(console.readPassword("Password: "));
		 		
				httpClient = HttpClients.createDefault();
				
				//HTTP Post request to Okta API for session token   
				httpost = new HttpPost("https://" + oktaOrg + "/api/v1/authn");
				httpost.addHeader("Accept", "application/json");
				httpost.addHeader("Content-Type", "application/json");
				httpost.addHeader("Cache-Control", "no-cache");
				
				//construction of request JSON 
				JSONObject jsonObjRequest = new JSONObject();
				jsonObjRequest.put("username", oktaUsername);
				jsonObjRequest.put("password", oktaPassword);
			 
				StringEntity entity = new StringEntity(jsonObjRequest.toString(), HTTP.UTF_8);
				entity.setContentType("application/json");
				httpost.setEntity(entity);
				responseAuthenticate = httpClient.execute(httpost);
				
				requestStatus = responseAuthenticate.getStatusLine().getStatusCode();
				if (requestStatus== 400 || requestStatus==401){
					System.out.println("Invalid Credentials, Please try again.");
				}
				else if(requestStatus == 500){
					System.out.println("\nUnable to establish connection with: " + 
							oktaOrg + " \nPlease verify that your Okta org url is corrct and try again" );
					System.exit(0);
				}
				else if(requestStatus!=200){
					throw new RuntimeException("Failed : HTTP error code : "
					+ responseAuthenticate.getStatusLine().getStatusCode());
				}
			}
		
			//Retrieve and parse the Okta response for session token
			BufferedReader br = new BufferedReader(new InputStreamReader(
			(responseAuthenticate.getEntity().getContent())));
			
			String outputAuthenticate = br.readLine();
			JSONObject jsonObjResponse = new JSONObject(outputAuthenticate);
			String oktaSessionToken = jsonObjResponse.getString("sessionToken");
				
			// Part 2: Get the Identity Provider and Role ARNs.
			//Request for AWS SAML response containing roles 
			httpget = new HttpGet(oktaAWSAppURL + "?onetimetoken=" + oktaSessionToken);
			responseSAML = httpClient.execute(httpget);
		
			if(responseSAML.getStatusLine().getStatusCode() == 500){
				throw new UnknownHostException();
			}
			else if (responseSAML.getStatusLine().getStatusCode() != 200) {
				throw new RuntimeException("Failed : HTTP error code : "
						+ responseSAML.getStatusLine().getStatusCode());
			}
			
			//Parse SAML response
			BufferedReader brSAML = new BufferedReader(new InputStreamReader(
			(responseSAML.getEntity().getContent()))); 
			String outputSAML = "";
			
			while ((outputSAML = brSAML.readLine()) != null) {
				if (outputSAML.contains("SAMLResponse")) {
					resultSAML = outputSAML.substring(outputSAML.indexOf("value=") + 7, outputSAML.indexOf("/>") - 1);
				}
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch(UnknownHostException e){
			System.out.println("\nUnable to establish connection with AWS. \nPlease verify that your AWS app url is corrct and try again" );
			scanner.close();
			System.exit(0);
		}
		catch(ClientProtocolException e){
			System.out.println("\nNo Org found, enter you org in you oktaCredentials file" );
			scanner.close();
			System.exit(0);
		}
		catch (IOException e) {
			e.printStackTrace();
			scanner.close();
		}
		finally {
			try{
				responseAuthenticate.close();
				responseSAML.close();
				httpClient.close();
			}catch(Exception ex) {
				ex.printStackTrace();
			}
		}  
		
		// Part 3: Assume an AWS role using the SAML Assertion from Okta
		// Decode SAML response
		resultSAML = resultSAML.replace("&#x2b;", "+").replace("&#x3d;", "=");
		String resultSAMLDecoded = new String(Base64.decodeBase64(resultSAML));
		
		ArrayList<String> principalArns = new ArrayList<String>();
		ArrayList<String> roleArns = new ArrayList<String>();

		//When the app is not assigned to you no assertion is returned
		if(!resultSAMLDecoded.contains("arn:aws")){
			System.out.println("\nYou do not have access to AWS through Okta. \nPlease contact your administrator.");
			System.exit(0);
		}
		
		System.out.println("\nPlease choose the role you would like to assume: ");
		
		//Gather list of applicable AWS roles
		int i = 0;
		while (resultSAMLDecoded.indexOf("arn:aws") != -1) { 
			String resultSAMLRole = resultSAMLDecoded.substring(resultSAMLDecoded.indexOf("arn:aws"), resultSAMLDecoded.indexOf("</saml2:AttributeValue"));
			String[] parts = resultSAMLRole.split(",");
			principalArns.add(parts[0]);
			roleArns.add(parts[1]);	
			System.out.println("[ " + (i+1)  + " ]: " + roleArns.get(i));
			resultSAMLDecoded = (resultSAMLDecoded.substring(resultSAMLDecoded.indexOf("</saml2:AttributeValue") +1));
			i++;
		}

		//Prompt user for role selection
		int selection = -1;
		while (selection == -1) {
			System.out.print("Selection: ");
			String selectInput = scanner.next();
			try{
				selection = Integer.parseInt(selectInput) - 1;
				if (selection >= roleArns.size()) {
					InputMismatchException e = new InputMismatchException();
					throw e;
				}
			}
			catch (InputMismatchException e ) {
				System.out.println("Invalid input: Please enter a number corresponding to a role \n");
				selection = -1; 
			}
			catch (NumberFormatException e) {
				System.out.println("Invalid input: Please enter in a number \n");
				selection = -1; 
			}
		}
		
		scanner.close();
		String principalArn  = principalArns.get(selection);
		String roleArn = roleArns.get(selection);
		
		//use user credentials to assume AWS role
		AWSSecurityTokenServiceClient stsClient = new AWSSecurityTokenServiceClient(); 
		AssumeRoleWithSAMLRequest assumeRequest = new AssumeRoleWithSAMLRequest() 
		.withPrincipalArn(principalArn) 
		.withRoleArn(roleArn) 
		.withSAMLAssertion(resultSAML); 
		
		AssumeRoleWithSAMLResult assumeResult = stsClient.assumeRoleWithSAML(assumeRequest);

		// Part 4: Write the credentials to ~/.aws/credentials
		BasicSessionCredentials temporaryCredentials =
			new BasicSessionCredentials(
					assumeResult.getCredentials().getAccessKeyId(),
				assumeResult.getCredentials().getSecretAccessKey(),
				assumeResult.getCredentials().getSessionToken());
	
		String awsAccessKey = temporaryCredentials.getAWSAccessKeyId();
		String awsSecretKey = temporaryCredentials.getAWSSecretKey();
		String awsSessionToken = temporaryCredentials.getSessionToken();
	
		File file = new File (System.getProperty("user.home")+"/.aws/credentials");
		file.getParentFile().mkdirs();
	
		PrintWriter writer = new PrintWriter(file, "UTF-8");
		writer.println("[default]");
		writer.println("aws_access_key_id="+awsAccessKey);
		writer.println("aws_secret_access_key="+awsSecretKey);
		writer.println("aws_session_token="+awsSessionToken);
		writer.close();
		
		Calendar date = Calendar.getInstance();
		SimpleDateFormat dateFormat = new SimpleDateFormat();
		date.add(Calendar.HOUR,1);
		
		//change with file customization
		System.out.println("\n----------------------------------------------------------------------------------------------------------------------");
		System.out.println("Your new access key pair has been stored in the aws configuration file "
				+  System.getProperty("user.home") + "/.aws/credentials under the saml profile.");
		System.out.println("Note that it will expire at " +  dateFormat.format(date.getTime()));
		System.out.println("After this time you may safely rerun this script to refresh your access key pair.");
		System.out.println("To use this credential call the aws cli with the --profile option "
				+ "(e.g. aws --profile saml ec2 describe-instances)");
		System.out.println("----------------------------------------------------------------------------------------------------------------------");
	}
}