<?php

/**
 * DKIM署名検証
 * dkimstatus_plus
 */

class dkimstatus_plus extends rcube_plugin
{
    public $task = 'mail';

    var $rc;
    var $dkim_whitelist;

    function init()
    {
        $this->load_config();
        $this->rc = rcmail::get_instance();
        if ($this->rc->task == 'mail')
        {
            $this->include_script('js/dkimstatus_plus.js');
            $this->add_hook('messages_list', array($this, 'messages_list'));
            $this->add_hook('storage_init', array($this, 'storage_init'));
            if ($this->rc->config->get('robins_apikey') > '') {
                # securemark initialize
                $this->rc->get_cache('securemark');
                $this->rc->config->set('securemark_cache', 'db');
            } else {
                $this->dkim_whitelist = $this->rc->config->get('dkim_whitelist');
            }
            if ($this->rc->action == 'show' || $this->rc->action == 'preview') {
                $this->add_hook('message_load', array($this, 'message_load'));
                $this->add_hook('message_headers_output', array($this, 'message_headers_output'));
            } else if ($this->rc->action == '') {
                // with enabled_caching we're fetching additional headers before show/preview
                $this->add_hook('storage_init', array($this, 'storage_init'));
            }
        }
    }

    static function get_authentication_result($body) {
        $body = preg_replace('~\R~u', "\r\n", $body);
        if (!($dkim = new OpenDKIMVerify())) {
            error_log('KO:'.__LINE__.':'.$dkim->getError());
        }
        if (!($res = $dkim->chunk($body))) {
        //    error_log('KO:'.__LINE__.':'.$dkim->getError());
        }
        if (!($res = $dkim->chunk())) {
        //    error_log('KO:'.__LINE__.':'.$dkim->getError());
        }
        if (!$dkim->body('')) {
        //    error_log('KO:'.__LINE__.':'.$dkim->getError());
        }
        if (OpenDKIM::STAT_OK!=$dkim->eom()) {
        //    error_log('KO:'.__LINE__.':'.$dkim->getError());
        }
        $result = $dkim->getARSigs();
        $dkim = '';
        return $result;
    }

    function messages_list($args) {
        if(!isset($args['messages']) or !is_array(['messages'])) {
            return $args;
        }

        foreach($args['messages'] as $message) {
            $message->list_flags['extra_flags']['dkimstatus_results'] = array();
            $dkimFilterType = 'none';
            if (is_array($message->others) && isset($message->others['authentication-results'])) {
                $dkimFilterType = 'milter';
            }elseif (class_exists('OpenDKIMVerify')) {
                $ar = static::get_authentication_result($this->get_message_body($message));
                if ($ar) {
                    $message->others['authentication-results'] = explode("\n", $ar);
                    $dkimFilterType = 'opendkim_extension';
                }
            }
            if ($dkimFilterType != 'none') {
                $result = $this->message_headers($message);
                if ($result['image'] && $result['alt']) {
                    # nomarl dkim
                    $message->list_flags['extra_flags']['dkimstatus_results']
                        = $this->image($result['image'], $result['alt'], $result['title']);
                }
            }else{
                $from_domain = '';
                if (preg_match("/[@](([a-zA-Z0-9-]+\.)+[a-zA-Z]+)/", $message->from, $m)) {
                    $from_domain = $m[1];
                }
                if (array_key_exists($from_domain, $this->dkim_whitelist)) {
                    $message->list_flags['extra_flags']['dkimstatus_results']
                        = $this->image('red_ban.png', 'whitelisted_exception', '');
                }
            }
        }
        return $args;
    }

    function get_message_body($message) {
        $uid = $message->uid;
        return $this->rc->storage->conn->handlePartBody(
            $message->folder, $uid, true, null, null, null, null, true, 0);
    }

    function message_load($args) {
        $this->message = $args['object'];
        $this->uid = $this->message->uid;

        $this->all = $this->rc->storage->conn->handlePartBody(
            $this->message->folder, $this->uid, true, null, null, null, null, true, 0);
        return $args;
    }

    function storage_init($p)
    {
        $p['fetch_headers'] = trim($p['fetch_headers'].' '.strtoupper('Authentication-Results'));
        return $p;
    }

    function image($image, $alt, $title)
    {
        return '<img src="plugins/dkimstatus_plus/images/'
            .$image.'" alt="'.$this->gettext($alt).'" title="'.$this->gettext($alt)
            .htmlentities($title, ENT_QUOTES, 'UTF-8').'" /> ';
    }

    function message_headers_output($p) {
        $headers= $p['headers'];
        $dkimFilterType = 'none';
        if (is_array($headers->others) && isset($headers->others['authentication-results'])) {
            $dkimFilterType = 'milter';
        }elseif (class_exists('OpenDKIMVerify')) {
            $ar = static::get_authentication_result($this->get_message_body($this->message));
            if ($ar) {
                $headers->others['authentication-results'] = explode("\n", $ar);
                $dkimFilterType = 'opendkim_extension';
            }
        }
        $result = $this->message_headers($headers);
        if ($result['image'] && $result['alt']) {
            if ($result['alt'] == 'safetymarkedsender') {
                $p['output']['from']['value'] = '<a id="tb_label_safetysender" href="#" class="active"'.
                    ' onclick="window.open(\''.'https://robins.jipdec.or.jp/'.$result['robins_key'].'\');">'.
                    $this->image($result['image'], $result['alt'], $result['title']).
                    '</a>'.
                    $p['output']['from']['value'];
            } else {
                $p['output']['from']['value']
                    = $this->image($result['image'], $result['alt'], $result['title']) . $p['output']['from']['value'];
            }
        }
        return $p;
    }

    function message_headers($headers)
    {
        $this->add_texts('localization');

        $image = 'nosiginfo.png';
        $alt = 'nosignature';
        $robins_apikey = '';
        $robins_key = '';
        $results = '';
        if ($headers->others['authentication-results']) {
            $results = $headers->others['authentication-results'];
        }
        if ($results) {
            if (is_array($results)) {
                foreach ($results as $result) {
                    if(preg_match("/dkim=([a-zA-Z0-9]*)/", $result, $m)) {
                        $status = ($m[1]);
                        $res=$result;
                        if ($m[1] == 'pass') {
                            break;
                        }
                    }
                }
                $results=$res;
            } else {
                if(preg_match("/dkim=([a-zA-Z0-9]*)/", $results, $m)) {
                    $status = ($m[1]);
                }
            }

            if($status == 'pass') {
                if(preg_match("/[@](([a-zA-Z0-9-]+\.)+[a-zA-Z]+)/", $headers->from, $m)) {
                    $authordomain = $m[1];
                    if(preg_match("/header\.(d|i|from)=(([a-zA-Z0-9]+[_\.\-]?)+)?($authordomain)/", $results)) {
                        $image = 'blue_checked.png';
                        $alt = 'verifiedsender';
                        $title = $results;

                        # check domain exists
                        $robins_apikey = $this->rc->config->get('robins_apikey');
                        if ($robins_apikey > '') {
                            $securemark_db = new securemark_cache_db($robins_apikey);
                            $dkimdomain_json = $securemark_db->get_cached_dkim_domain($authordomain);
                            if ($dkimdomain_json) {
                                $dkimdomain = json_decode($dkimdomain_json);
                                $robins_key = $dkimdomain->robinsKey;
                                $corporationNameJp = $dkimdomain->corporationNameJp;
                                $corporationNameEn = $dkimdomain->corporationNameEn;
                                $image = 'specialdata_published_101.png';
                                $alt = 'safetymarkedsender';
                                $title = "\r\n\r\n".
                                    "事業者名:".mb_convert_encoding($corporationNameJp, 'UTF-8').
                                    "\r\n\r\n".$results;
                            }
                        } else {
                            list($corporationNameJp, $robins_key )
                                = $this->dkim_whitelist[$authordomain];
                            if ($corporationNameJp) {
                                $image = 'green_checked.png';
                                $alt = 'whitelisted';
                                $title = "\r\n\r\n".
                                    "事業者名:".mb_convert_encoding($corporationNameJp, 'UTF-8').
                                    "\r\n\r\n".$results;
                            }
                        }
                    } else {
                        $image = 'gray_checked.png';
                        $alt = 'thirdpartysig';
                        $title = $results;
                    }
                }

            } else if ($status) {
                $image = 'red_warning.png';
                $alt = 'invalidsignature';
                $title = $results;
            }
        }
        return array('image' => $image, 'alt' => $alt, 'title' => $title, 'robins_key' => $robins_key);
    }
}
# vim: ft=php et sts=4 sw=4
