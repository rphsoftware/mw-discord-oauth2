<?php

namespace MediaWiki\Extension\RphDiscordOauth;

use MediaWiki\MediaWikiServices;

class SpecialDiscordAuthorize extends \UnlistedSpecialPage {
    public function __construct()
    {
        parent::__construct( "DiscordAuthorize" );
    }

    public function execute( $sub ) {
        global $wgRequest;
        if ($wgRequest->getSessionData('discord_validated') === "YES") {
            $this->getOutput()->setPageTitle("Logging in with discord");
            $this->getOutput()->addHTML("<h2>Hello " . htmlentities($wgRequest->getSessionData('discord_username')) . "! You can now create an account!</h2><a href='/Special:CreateAccount'>Continue to account creation</a>");
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

        $out->setPageTitle("Logging in with discord");
        $state = bin2hex(openssl_random_pseudo_bytes(64));
        $wgRequest->getSession()->set("discord_oauth_state", $state);
        $out->addHTML("
<strong>For security reasons, this wiki requires you associate your Discord Account with your session prior to making an account here.</strong>
<p>This process will let us know the following:</p>
<ul>
    <li>Your Discord ID</li>
    <li>Your Discord Username and Tag</li>
    <li>Your Discord Profile Picture</li>
    <li>The Email Address associated with your Discord Account</li>
</ul>
<p>You are only required to do this once, afterwards you will be able to make an account and later log in to it normally.</p>
<a href='https://discord.com/oauth2/authorize?state=$state&client_id=$clientId&response_type=code&scope=identify%20email&redirect_uri=$callbackUri'>Click here to continue.</a>
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
        $dbr = $lb->getConnectionRef( DB_PRIMARY );
        $res = $dbr->select('discord_oauth2_users', ['id', 'discordId'], [
            'discordId' => $tokenResponse['id']
        ], __METHOD__, []);
        if ($res->numRows() > 0) {
            $this->getOutput()->addHTML("<h2>This discord account is already associated with a wiki account. Please log in instead.</h2>");
            $this->__render_prompt();
            return;
        }
        $wgRequest->getSession()->set('discord_user_id', $tokenResponse['id']);
        $wgRequest->getSession()->set('discord_validated', "YES");
        $wgRequest->getSession()->set('discord_username', $tokenResponse['username']);

        $this->getOutput()->setPageTitle("Logging in with discord");
        $this->getOutput()->addHTML("<h2>Hello " . htmlentities($tokenResponse['username']) . "! You can now create an account!</h2><a href='/Special:CreateAccount'>Continue to account creation</a>");
    }

    protected function getGroupName() {
        return 'other';
    }
}