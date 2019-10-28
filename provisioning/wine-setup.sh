#!/bin/sh

# This script prepares a wine environment to work for Postbox

# Required packages:
# curl unzip wine python2 perl p7zip-full
#
# Required pre-downloaded Windows files:
# Postbox
# Perl
# GnuPG

PARENTDIR=$HOME/.wine/drive_c/Enigmail
#rm -rf $PARENTDIR
mkdir -p $PARENTDIR/test-profile/extensions

ln -s $(pwd) $PARENTDIR/enigmail-src
ln -s $(pwd)/Postbox $PARENTDIR/Postbox
ln -s $(pwd)/Perl $PARENTDIR/Perl
ln -s $(pwd)/app/bin $HOME/.wine/drive_c/gnupg

echo "C:\\\\Enigmail\\\\enigmail-src\\\\build-pbx\\\\dist\\\\" > "$PARENTDIR/test-profile/extensions/{847b3a00-7ab1-11d4-8f02-006008948af5}"
cat << EOT > "$PARENTDIR/test-profile/prefs.js"
user_pref("extensions.autoDisableScopes", 14);
user_pref("browser.dom.window.dump.enabled", true);
user_pref("extensions.enigmail.logDirectory", "C:\\Enigmail\\test-profile");
user_pref("extensions.enigmail.juniorMode", 0);
user_pref("devtools.debugger.prompt-connection", false);
user_pref("mail.account.account1.identities", "id1");
user_pref("mail.account.account1.server", "server2");
user_pref("mail.account.lastKey", 1);
user_pref("mail.accountmanager.accounts", "account1");
user_pref("mail.accountmanager.localfoldersserver", "server1");
user_pref("mail.append_preconfig_smtpservers.version", 2);
user_pref("mail.identity.id1.archive_folder", "mailbox://dummy2@localhost/Archives");
user_pref("mail.identity.id1.compose_html", true);
user_pref("mail.identity.id1.draft_folder", "mailbox://nobody@Local%20Folders/Drafts");
user_pref("mail.identity.id1.enablePgp", true);
user_pref("mail.identity.id1.fcc_folder", "mailbox://nobody@Local%20Folders/Sent");
user_pref("mail.identity.id1.fullName", "John Doe I.");
user_pref("mail.identity.id1.pgpkeyId", "ABCDEF0123456789");
user_pref("mail.identity.id1.pgpKeyMode", 1);
user_pref("mail.identity.id1.stationery_folder", "mailbox://nobody@Local%20Folders/Templates");
user_pref("mail.identity.id1.useremail", "testing@domain.invalid");
user_pref("mail.root.none-rel", "[ProfD]Mail");
user_pref("mail.root.pop3-rel", "[ProfD]Mail");
user_pref("mail.server.server1.directory-rel", "[ProfD]Mail/Local Folders");
user_pref("mail.server.server1.hostname", "Local Folders");
user_pref("mail.server.server1.name", "Local Folders");
user_pref("mail.server.server1.nextFilterTime", 10);
user_pref("mail.server.server1.storeContractID", "@mozilla.org/msgstore/berkeleystore;1");
user_pref("mail.server.server1.type", "none");
user_pref("mail.server.server1.login_at_startup", false);
user_pref("mail.server.server1.userName", "nobody");
user_pref("mail.server.server2.acPreferEncrypt", 1);
user_pref("mail.server.server2.check_new_mail", false);
user_pref("mail.server.server2.directory-rel", "[ProfD]Mail/localhost");
user_pref("mail.server.server2.hostname", "localhost");
user_pref("mail.server.server2.name", "Enigmail Unit Test");
user_pref("mail.server.server2.nextFilterTime", 10);
user_pref("mail.server.server2.storeContractID", "@mozilla.org/msgstore/berkeleystore;1");
user_pref("mail.server.server2.type", "pop3");
user_pref("mail.server.server2.userName", "dummy");
user_pref("mail.server.server2.login_at_startup", false);
user_pref("extensions.enigmail.configuredVersion", "99.0");
user_pref("mail.shell.checkDefaultClient", false);
EOT

echo '{"mainFile": "main.js", "logFile": null}' >  "$PARENTDIR/test-profile/jsunit.json"

cat <<EOT > pbx-wrapper.sh
#!/bin/sh
export PL_PATH=C:\\\\Enigmail\\\\Perl\\\\bin\\\\perl.exe
/usr/bin/wine C:\\\\Enigmail\\\\Postbox\\\\postbox.exe --no-remote --profile C:\\\\Enigmail\\\\test-profile
killall gpg-agent.exe
EOT

chmod +x pbx-wrapper.sh
#./configure --enable-postbox --enable-tests --with-tb-path=$(pwd)/pbx-wrapper.sh
