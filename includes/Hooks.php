<?php
namespace MediaWiki\Extension\RphDiscordOauth;

use DatabaseUpdater;

class Hooks {
    public static function onLoadExtensionSchemaUpdates( DatabaseUpdater $updater ) {
        $updater->addExtensionTable(
            'discord_oauth2_users',
            dirname(__FILE__) . '/sql/tables.sql'
        );
    }

    public static function onBeforePageDisplay(\SpecialPage $special) {
        global $wgRequest;
        if ($wgRequest->getQueryValues()["title"] === "Special:CreateAccount") {
           // $out->redirect("Special:DiscordAuthorize");
            if ($wgRequest->getSessionData('discord_validated') !== "YES") {
                $special->getOutput()->redirect("/Special:DiscordAuthorize");
            }
        }
    }
}
