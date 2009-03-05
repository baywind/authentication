/* This is example code from "Practical WebObjects" book by Charles Hill and Sacha Mallais
 *    http://www.apress.com/book/view/9781590592960
 */

package com.apress.practicalwo.practicalutilities;

import com.webobjects.appserver.WORequest;
import com.webobjects.foundation.NSArray;

/**
 * A collection of methods useful with WORequest.  These would make a good addtion
 * to a sub-class of WORequest.
 * 
 * @author Charles Hill and Sacha Mallais
 */
public class WORequestAdditions
{
    // Add more options here (e.g. for IIS, NSAPI, etc.), if neccessary...
    public static final NSArray HOST_NAME_KEYS = new NSArray(new Object[]
        {"host","x-webobjects-server-name", "server_name", "Host", "http_host"});
        
    // Add more options here (e.g. for IIS, NSAPI, etc.), if neccessary...
    public static final NSArray SERVER_PORT_KEYS = new NSArray(new Object[]
        {"x-webobjects-server-port", "SERVER_PORT"});        
        
    // Add more options here if neccessary...
    public static final NSArray IP_ADDRESS_KEYS = new NSArray(new Object[]
        {"x-webobjects-remote-addr", "remote_addr"});        
        

    /**
     * Returns <code>true</code> if the request was made via https/SSL, 
     * <code>false</code> otherwise.  It makes the rather grand assumption that
     * all HTTPS connections are on port 443.
     *
     * @return <code>true</code> if the request was made via https/SSL, 
     * <code>false</code> otherwise.
     */
    static public boolean isSecure(WORequest request)
    {
        /** require [valid_param] request != null; **/

        boolean isSecure = false;

        // The method of determining whether the request was via HTTPS depends 
        // on the adaptor / the web server.  
        
        // First we try and see if the request was made on the standard https port
        
        // Apache and some other web servers use this to indicate HTTPS mode.
        // This is much better as it does not depend on the port number used.
        String httpsMode = request.headerForKey("https");

        // If either the https header is 'on' or the server port is 443 then we 
        // consider this to be an HTTP request.
        isSecure = ( ((httpsMode != null) && httpsMode.equalsIgnoreCase("on")) ||
					 (serverPort(request)==443) );//((serverPort != null) && serverPort.equals("443")) );

        return isSecure;
    }

    public static int serverPort(WORequest request) {
		String serverPort = null;
        for (int i = 0; (serverPort == null) && (i < SERVER_PORT_KEYS.count()); i++)
        {
            serverPort = request.headerForKey((String) SERVER_PORT_KEYS.objectAtIndex(i));
        }
		return (serverPort==null)?0:Integer.parseInt(serverPort);
	}
    
    
    /**
     * Returns the host name (a.k.a. server name, domain name) used in 
     * this request.  The request headers are examined for the keys in 
     * HOST_NAME_KEYS to determine the name.
     *
     * @param request the request to get the hostname from
     * @return the host name used in this request.
     */
    static public String hostName(WORequest request)
    {
        /** require [valid_param] request != null; **/

        String hostName = null;
        for (int i = 0; (hostName == null) && (i < HOST_NAME_KEYS.count()); i++)
        {
            hostName = request.headerForKey((String) HOST_NAME_KEYS.objectAtIndex(i));
        }

        return hostName;

        /** ensure [valid_result] Result != null; **/
     }
     


    /**
     * Returns the IP address that this request originated from.  The request 
     * headers are examined for the keys in IP_ADDRESS_KEYS to determine the 
     * address.
     *
     * @param request the request to get the hostname from
     * @return the IP address the request came from.
     */
    static public String originatingIPAddress(WORequest request)
    {
        /** require [valid_param] request != null; **/

        String originatingIPAddress = null;
        for (int i = 0; (originatingIPAddress == null) && (i < IP_ADDRESS_KEYS.count()); i++)
        {
            originatingIPAddress = request.headerForKey((String) IP_ADDRESS_KEYS.objectAtIndex(i));
        }

        return originatingIPAddress;

        /** ensure [valid_result] Result != null; **/
     }
}
