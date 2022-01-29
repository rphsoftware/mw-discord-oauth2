<?php

namespace MediaWiki\Extension\RphDiscordOauth;

use MediaWiki\MediaWikiServices;

/// The following function is licensed separately under the terms of CC BY-SA 4.0
/// Link to original: https://stackoverflow.com/a/4356295
function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

class SpecialDiscordAuthorize extends \UnlistedSpecialPage {
    public function __construct()
    {
        parent::__construct( "DiscordAuthorize" );
    }

    public function execute( $sub ) {
        global $wgRequest;
        if ($wgRequest->getSessionData('discord_validated') === "YES") {
            $this->getOutput()->setPageTitle("Log in with Discord");
            $this->getOutput()->redirect("/Special:CreateAccount");
            return;
        }
        if ($sub === "Redirect") {
            $this->__handler();
            return;
        }

        $this->__render_prompt();
    }

    private function __render_prompt() {
        global $wgRequest;
        $out = $this->getOutput();
        $config = $this->getConfig();

        $clientId = $config->get("DiscordOauth2ClientId");
        $callbackUri = urlencode($config->get("DiscordOauth2RedirectUri"));

        $out->setPageTitle("Log in with Discord");
        $state = generateRandomString(64);
        $wgRequest->getSession()->set("discord_oauth_state", $state);
        $out->addHTML("
<b>For security reasons, this wiki requires you associate your Discord account with your session in order to create an account.</b>
<p>This process will let us know the following:</p>
<ul>
    <li>Your Discord ID</li>
    <li>Your Discord username and tag</li>
    <li>Your Discord profile picture</li>
    <li>The Email address associated with your Discord account</li>
</ul>
<p>You are only required to do this once, afterwards you will be able to make an account and later log in to it normally.</p>
<b><a href='https://discord.com/oauth2/authorize?state=$state&client_id=$clientId&response_type=code&scope=identify%20email&redirect_uri=$callbackUri'>Click here to log in with Discord.</a></b>
");
    }

    private function __handler() {
        global $wgRequest;
        if ($wgRequest->getSessionData('discord_oauth_state') !== $wgRequest->getQueryValues()['state'] || !isset($wgRequest->getQueryValues()['state'])) {
            $this->getOutput()->addHTML("<h2>The previous login attempt failed: Reason code 1</h2>");
            $this->__render_prompt();
            return;
        }
        $config = $this->getConfig();

        $clientId = $config->get("DiscordOauth2ClientId");
        $clientSecret = $config->get("DiscordOauth2ClientSecret");
        $callbackUri = $config->get("DiscordOauth2RedirectUri");

        $postData = http_build_query(
            array(
                "client_id" => $clientId,
                "client_secret" => $clientSecret,
                "grant_type" => "authorization_code",
                "code" => $wgRequest->getQueryValues()['code'],
                "redirect_uri" => $callbackUri,
                "scope" => "identify email"
            )
        );
        $sc = stream_context_create(
            array(
                'http'=> array(
                    'method'=>"POST",
                    'header'=>"Content-Type: application/x-www-form-urlencoded",
                    'content'=>$postData
                )
            )
        );
        $fp = fopen('https://discord.com/api/v9/oauth2/token', 'r', false, $sc);
        if ($fp === false) {
            $this->getOutput()->addHTML("<h2>The previous login attempt failed: Reason code 2</h2>");
            $this->__render_prompt();
            return;
        }
        $contents = stream_get_contents($fp);
        fclose($fp);

        $tokenResponse = json_decode($contents, true);

        if (!isset($tokenResponse['token_type']) || !isset($tokenResponse['access_token'])) {
            $this->getOutput()->addHTML("<h2>The previous login attempt failed: Reason code 3</h2>");
            $this->__render_prompt();
            return;
        }

        $token_type = $tokenResponse['token_type'];
        $access_token = $tokenResponse['access_token'];

        $sc = stream_context_create(
            array(
                'http'=>array(
                    'method'=>'GET',
                    'header'=>"Authorization: $token_type $access_token"
                )
            )
        );
        $fp = fopen('https://discord.com/api/v9/users/@me', 'r', false, $sc);
        if ($fp === false) {
            $this->getOutput()->addHTML("<h2>The previous login attempt failed: Reason code 4</h2>");
            $this->__render_prompt();
            return;
        }
        $contents = stream_get_contents($fp);
        fclose($fp);

        $tokenResponse = json_decode($contents, true);

        if (!isset($tokenResponse['id'])) {
            $this->getOutput()->addHTML("<h2>The previous login attempt failed: Reason code 5</h2>");
            $this->__render_prompt();
            return;
        }

        $lb = MediaWikiServices::getInstance()->getDBLoadBalancer();
        $dbr = $lb->getConnectionRef( $lb::DB_PRIMARY );
        $res = $dbr->select('discord_oauth2_users', ['id', 'discordId'], [
            'discordId' => $tokenResponse['id']
        ], __METHOD__, []);
        if ($res->numRows() > 0) {
            $this->getOutput()->addHTML("<h2>This Discord account is already associated with an existing account. Please log in instead.</h2>");
            $this->__render_prompt();
            return;
        }
        $wgRequest->getSession()->set('discord_user_id', $tokenResponse['id']);
        $wgRequest->getSession()->set('discord_validated', "YES");
        $wgRequest->getSession()->set('discord_username', $tokenResponse['username']);

        $this->getOutput()->setPageTitle("Logging in with discord");
        //$this->getOutput()->addHTML("<h2>Hello " . htmlentities($tokenResponse['username']) . "! You can now create an account!</h2><a href='/Special:CreateAccount'>Continue to account creation</a>");
        $this->getOutput()->redirect("/Special:CreateAccount");
    }

    protected function getGroupName() {
        return 'other';
    }
}