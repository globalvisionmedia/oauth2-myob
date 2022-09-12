# MYOB Provider for OAuth 2.0 Client
This package provides MYOB OAuth 2.0 support for the PHP League's OAuth 2.0 Client.

# Installation
    composer require globalvisionmedia/oauth2-myob

# Obtaining an MYOB access key
1. To get a key you will need to be part of the MYOB Developer Program (https://developer.myob.com/program/become-a-myob-developer-partner/)
2. After you obtain an account, log in and click the "Developer" tab of my.myob.com.au
3. Click the Register App button to create a key
4. The redirect API must be exactly the same (including the http:// or https://) as the redirectUri below and is the URL of your application

# Usage
Usage is the same as The League's OAuth client, using \GlobalVisionMedia\OAuth2\MYOBClient\Provider\MYOB as the provider, except for the following:

1. MYOB does not rely exclusively on OAUth2 to log you in. OAUth2 is used to provide access to the APIs but not to your MYOB data file. This requires a second login which returns a "Company URL". This provider handles both logins but requires you to provide your MYOB login details in addition to the standard OAUth2 credentials. (see Authorisation Code Flow, below)

2. MYOB's APIs are throttled - the documented limit is 8 calls per second (and a large number per day) but the throttling appears to be buggy and you will likely find that you receive API Access Limit Exceeded errors no matter what limits you impose unfortunately. However you will be able to create an application that works fairly reliably if you follow the guidelines under Sample Application (below) qnd add a failsafe that detects the throttling, pauses and retries.


# Instantiation
    $provider = new \GlobalVisionMedia\OAuth2\MYOBClient\Provider\MYOB([
        'clientId'                => 'yourId',          // The Key assigned to you by MYOB
        'clientSecret'            => 'yourSecret',      // The Secret assigned to you by MYOB
        'redirectUri'             => 'yourRedirectUri'  // The Redirect Uri you specified for your app on MYOB
        'username'                => 'yourUsername',    // The username you use when you log into MYOB
        'password'                => 'yourPassword',    // The password you use to log into MYOB
        'companyName'             => 'yourCompany'      // The name of your company file. This appears in the "Welcome" screen when you log into MYOB
    ]);
    
# Tip (also applies to other providers)
    When you instantiate your provider, you can also pass a second parameter containing a collaborator for your httpClient.
    Doing that means you can define your own Guzzle client and do things such as:
    
      1. Setting Guzzle into debug mode, or
      2. Adding a rate limiter mildeware (composer require spatie/guzzle-rate-limiter-middleware)
      
    
    use GuzzleHttp\Client;
    use GuzzleHttp\HandlerStack;
    use Spatie\GuzzleRateLimiterMiddleware\RateLimiterMiddleware;

    // Add a rate limiter
    $stack=HandlerStack::create();
    $stack->push(RateLimiterMiddleware::perSecond($this->getPerSecondRateLimit()));
    $options=['debug' => $debug, 'exceptions' => false, 'handler' => $stack];
    $httpClient = new Client($options);

    $this->provider = \GlobalVisionMedia\OAuth2\MYOBClient\Provider\MYOB([
        'redirectUri'       => CALLBACK_URI,
        'clientId'          => MYOB_CLIENT_ID,
        'clientSecret'      => MYOB_CLIENT_SECRET,
        'username'          => MYOB_USERNAME,
        'password'          => MYOB_PASSWORD,
        'companyName'       => MYOB_COMPANY_NAME
      ],
      ['httpClient'         => $httpClient]);

# Sample application
    <?php
    require __DIR__ . '/vendor/autoload.php';

    // This is a prebuilt rate limiter for guzzle - unfortunately MYOB does not seem to work as documented any you may need to add additional sleep() calls.
  
    use GuzzleHttp\Client;
    use GuzzleHttp\HandlerStack;
    use Spatie\GuzzleRateLimiterMiddleware\RateLimiterMiddleware;
  
    define('CALLBACK_URI','https://xxxx.yyyyy.com/myApp.php');       // set to the URL for this script
  
    define('MYOB_CLIENT_ID','xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'); // set to your client ID
    define('MYOB_CLIENT_SECRET','xxxxxxxxxxxxxxxxxxxxxxxx');         // set to your secret
    define('MYOB_COMPANY_NAME','My Company File Name');              // set to your company database file
    define('MYOB_USERNAME','xxxxxx@myemail.com');                    // set to your MYOB login
    define('MYOB_PASSWORD','xxxxxxxxxx');                            // set to your MYOB pass
  
    define('CACHEDIR','/tmp/');                                      // a writeable area for storing tokens
  
  
    class myMYOB {
  
      public function __construct($debug=false) {
        $this->cache=CACHEDIR.'_API_TOKEN_CACHE_'.md5(__FILE__.get_class($this));
  
        // Add the rate limiter
        $stack=HandlerStack::create();
        $stack->push(RateLimiterMiddleware::perSecond($this->getPerSecondRateLimit()));
        $options=['debug' => $debug, 'exceptions' => false, 'handler' => $stack];
        $httpClient = new Client($options);
  
        $this->provider = \GlobalVisionMedia\OAuth2\MYOBClient\Provider\MYOB([
            'redirectUri'       => CALLBACK_URI,
            'clientId'          => MYOB_CLIENT_ID,
            'clientSecret'      => MYOB_CLIENT_SECRET,
            'username'          => MYOB_USERNAME,
            'password'          => MYOB_PASSWORD,
            'companyName'       => MYOB_COMPANY_NAME
          ],
          ['httpClient'         => $httpClient]);
  
        // First check our cache to see if we have an existing token. This sppeds the application by avoiding the need to re-authenticate.
        if (file_exists($this->cache)) {
          $this->accessToken=unserialize(file_get_contents($this->cache));
          if ($this->accessToken->hasExpired()) {
            $this->accessToken=$this->provider->getAccessToken('refresh_token', ['refresh_token'=>8]);
          }
        } elseif (!isset($_GET['code'])) {
          // If we don't have an authorization code then get one
          $authUrl = $this->provider->getAuthorizationUrl();
          $_SESSION['oauth2state'] = $this->provider->getState();
  
          header('Location: '.$authUrl);
          exit;
  
          // Check given state against previously stored one to mitigate CSRF attack
        } elseif (empty($_GET['state']) ||
                  (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
          if (isset($_SESSION['oauth2state'])) unset($_SESSION['oauth2state']);
          exit('Invalid state');
  
          // Try to get an access token using the authorisation code grant.
        } else try {
          $this->accessToken = $this->provider->getAccessToken('authorization_code', [ 'code' => $_GET['code'] ]);
  
          // Cache the token
          file_put_contents($this->cache,serialize($this->accessToken));
  
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
          // Failed to get the access token or user details.
          exit($e->getMessage());
        }
      }
  
      public function apiCall($method, $url, $pageSize=1000, $filter=null) {
        if (strpos($url,"https://")===false) {  // is this a nextpage link? if so leave url unchanged
          // have we logged into our datafile yet?
          if (!isset($this->companyURL)) {
            $this->companyURL=$this->provider->getCompanyUrl($this->accessToken);
          }
          $url=$this->companyURL.$url.'?'.$filter; // add any OData filters - see https://apisupport.myob.com/hc/en-us/articles/360000496136-OData-filter-Tips-Tricks
        }
        $request=$this->provider->getAuthenticatedRequest($method, $url, $this->accessToken);
        try {
          $response = $this->provider->getResponse($request);
        } catch (\GuzzleHttp\Exception\ClientException $e) {
  
          // See if we have been throttled despite our best efforts...
          if (strpos($message,"API key has exceeded the per-second rate limit")!==false) {
            sleep(5);  // wait 5 seconds and try again
            return $this->apiCall($method,$url);
          }
          die("Error: ".$e->getMessage());
        }
  
        if (strtolower($method)=='get') {
          $parsed = json_decode($response->getBody(),true);
          if (json_last_error() !== JSON_ERROR_NONE) {
            die ("Invalid JSON received from API");
          }
          return $parsed;
        } else {
          return true;
        }
      }
  
      // This function retrieves paginated data as a single array
      public function fetchAll($method, $url, $pageSize=1000, $filter=null) {
        $allResults=array();
        do {
          $result=$this->apiCall($method,$url,$pageSize,$filter);
          $allResults=array_merge($allResults,$result['Items']);
          $url = $result['NextPageLink'];
        } while (!empty($url));
        return $allResults;
      }
  
    }
  
    session_start();
    $myob=new myMYOB();
    print_r($myob->fetchAll('GET', '/GeneralLedger/Job'));
