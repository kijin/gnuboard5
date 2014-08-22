<?php
if (!defined('_GNUBOARD_')) exit;

// 비밀번호 암호화(해싱) - 가능하면 직접 호출하지 말고 common.lib.php의 hash_password() 함수를 통할 것
function create_password_hash($password, $algorithm)
{
    switch ($algorithm)
    {
        case 'password':
            return '*'.strtoupper(sha1(sha1($password, true)));
        
        case 'md5':
            return md5($password);
        
        case 'sha1':
            return sha1($password);
        
        case 'sha256':
        case 'sha384':
        case 'sha512':
            if (function_exists('hash_algos') && in_array($algorithm, hash_algos()))
            {
                return hash($algorithm, $password);
            }
            elseif (function_exists('mhash') && defined('MHASH_' . strtoupper($algorithm)))
            {
                return bin2hex(mhash(constant('MHASH_' . strtoupper($algorithm)), $password));
            }
            else
            {
                return false;
            }
        
        case 'pbkdf2':
            $salt = create_secure_salt(24, 'alnum');
            $length = 32;
            $iterations = 8192;
            $pbkdf2 = pbkdf2('sha256', $password, $salt, $length, $iterations);
            if ($pbkdf2 !== false)
            {
                return 'sha256:'.$iterations.':'.$salt.':'.base64_encode($pbkdf2);
            }
            else
            {
                return false;
            }
        
        case 'bcrypt':
            if (version_compare(PHP_VERSION, '5.3.7', '>=') && defined('CRYPT_BLOWFISH'))
            {
                $work_factor = 8;
                $salt = '$2y$'.sprintf('%02d', $work_factor).'$'.create_secure_salt(22, 'alnum');
                return crypt($password, $salt);
            }
            else
            {
                return false;
            }
        
        default:
            return false;
    }
}

// 위의 함수로 암호화(해싱)된 비밀번호 체크 - 가능하면 직접 호출하지 말고 common.lib.php의 check_password() 함수를 통할 것
function check_password_hash($password, $hash)
{
    if (strlen($hash) === 16)  // OLD_PASSWORD()
    {
        $row = sql_fetch("SELECT OLD_PASSWORD('$password') AS pass");
        return $row['hashed_pass'] === $hash;
    }
    elseif (strlen($hash) === 41 && $hash[0] === '*')  // PASSWORD()
    {
        return strtoupper(sha1(sha1($password, true))) === substr($hash, 1);
    }
    elseif (ctype_xdigit($hash))
    {
        switch (strlen($hash))
        {
            case 32:
                return md5($password) === $hash;
            
            case 40:
                return sha1($password) === $hash;
            
            case 64:
                $algorithm = isset($algorithm) ? $algorithm : 'sha256';
            case 96:
                $algorithm = isset($algorithm) ? $algorithm : 'sha384';
            case 128:
                $algorithm = isset($algorithm) ? $algorithm : 'sha512';
                
            default:
                if (!isset($algorithm))
                {
                    return false;
                }
                elseif (function_exists('hash_algos') && in_array($algorithm, hash_algos()))
                {
                    return hash($algorithm, $password) === $hash;
                }
                elseif (function_exists('mhash') && defined('MHASH_' . strtoupper($algorithm)))
                {
                    return bin2hex(mhash(constant('MHASH_' . strtoupper($algorithm)), $password)) === $hash;
                }
                else
                {
                    return false;
                }
        }
    }
    elseif (preg_match('/^sha256:[0-9]+:[^:]+:[^:]+$/', $hash))  // PBKDF2
    {
        list($algorithm, $iterations, $salt, $pbkdf2) = explode(':', $hash);
        $pbkdf2 = @base64_decode($pbkdf2);
        return pbkdf2($algorithm, $password, $salt, strlen($pbkdf2), $iterations) === $pbkdf2;
    }
    elseif (preg_match('/^\$2[axy]\$[0-9]{2}\$/', $hash))  // bcrypt
    {
        if (version_compare(PHP_VERSION, '5.3.7', '>=') && defined('CRYPT_BLOWFISH'))
        {
            return crypt($password, $hash) === $hash;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}

// 현재 설정과 다른 알고리듬으로 암호화(해싱)된 비밀번호를 감지
function algorithm_needs_upgrade($hash)
{
    if (!defined('G5_HASHING_ALGORITHM')) return false;
    if (!defined('G5_UPGRADE_ALGORITHM') || !G5_UPGRADE_ALGORITHM) return false;
    
    switch (G5_HASHING_ALGORITHM)
    {
        case 'password':
            return (strlen($hash) !== 41 || $hash[0] !== '*' || !ctype_xdigit(substr($hash, 1)));
        
        case 'md5':
            return (strlen($hash) !== 32 || !ctype_xdigit($hash));
        
        case 'sha1':
            return (strlen($hash) !== 40 || !ctype_xdigit($hash));
        
        case 'sha256':
            return (strlen($hash) !== 64 || !ctype_xdigit($hash));
        
        case 'sha384':
            return (strlen($hash) !== 96 || !ctype_xdigit($hash));
        
        case 'sha512':
            return (strlen($hash) !== 128 || !ctype_xdigit($hash));
        
        case 'pbkdf2':
            return !preg_match('/^sha256:[0-9]+:[^:]+:[^:]+$/', $hash);
        
        case 'bcrypt':
            return !preg_match('/^\$2[axy]\$[0-9]{2}\$/', $hash);
        
        default:
            return false;
    }
}

// 회원 비밀번호를 새로운 알고리듬으로 업데이트
function upgrade_password_algorithm($mb_id, $password, $algorithm)
{
    global $g5;
    $hash = create_password_hash($password, $algorithm);
    $result = sql_query("UPDATE {$g5['member_table']} SET mb_password = '$hash' WHERE mb_id = '$mb_id'");
    return $result ? $hash : false;
}

// 솔트 생성 함수
function create_secure_salt($bytes, $format = 'hex')
{
    // 필요한 엔트로피 측정
    if ($format === 'hex')
    {
        $entropy_required_bytes = ceil($bytes / 2);
    }
    elseif ($format === 'alnum')
    {
        $entropy_required_bytes = ceil($bytes * 3 / 4);
    }
    else
    {
        $entropy_required_bytes = $bytes;
    }
    
    // 현재 시스템에서 사용 가능한 최적의 엔트로피를 선택
    if (function_exists('openssl_random_pseudo_bytes'))
    {
        $entropy = openssl_random_pseudo_bytes($entropy_required_bytes);
    }
    elseif (function_exists('mcrypt_create_iv') && defined('MCRYPT_DEV_URANDOM'))
    {
        $entropy = mcrypt_create_iv($entropy_required_bytes, MCRYPT_DEV_URANDOM);
    }
    elseif (defined('PHP_OS') && !strncmp(PHP_OS, 'Linux', 5) && @is_readable('/dev/urandom'))
    {
        $fp = fopen('/dev/urandom', 'rb');
        $entropy = fread($fp, $entropy_required_bytes);
        fclose($fp);
    }
    else
    {
        $entropy = '';
        for ($i = 0; $i < $entropy_required_bytes; $i += 2)
        {
            $entropy .= pack('S', mt_rand(0, 65535));
        }
    }
    
    // 엔트로피 믹싱
    $output = '';
    for ($i = 0; $i < $bytes; $i += 20)
    {
        $output .= sha1($entropy . $i . rand(), true);
    }
    
    // 원하는 포맷으로 인코딩하여 반환
    if ($format === 'hex')
    {
        return substr(bin2hex($output), 0, $bytes);
    }
    elseif ($format === 'alnum')
    {
        $salt = substr(base64_encode($output), 0, $bytes);
        $replacements = chr(rand(65, 90)) . chr(rand(97, 122)) . rand(0, 9);
        return strtr($salt, '+/=', $replacements);
    }
    else
    {
        return substr($output, 0, $bytes);
    }
}

// PBKDF2 함수
function pbkdf2($algorithm, $password, $salt, $length, $iterations)
{
    if (function_exists('hash_pbkdf2') && in_array($algorithm, hash_algos()))
    {
        return hash_pbkdf2($algorithm, $password, $salt, $iterations, $length, true);
    }
    elseif (function_exists('hash_algos') && in_array($algorithm, hash_algos()))
    {
        $output = '';
        $block_count = ceil($length / strlen(hash($algorithm, '', true))); // key length divided by the length of one hash
        for ($i = 1; $i <= $block_count; $i++)
        {
            $last = $salt . pack('N', $i); // $i encoded as 4 bytes, big endian
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true); // first iteration
            for ($j = 1; $j < $iterations; $j++) // The other $count - 1 iterations
            {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }
        return substr($output, 0, $length);
    }
    elseif (function_exists('mhash') && defined('MHASH_' . strtoupper($algorithm)))
    {
        $mhash_algorithm = constant('MHASH_' . strtoupper($algorithm));
        $output = '';
        $block_count = ceil($length / strlen(mhash($mhash_algorithm, ''))); // key length divided by the length of one hash
        for ($i = 1; $i <= $block_count; $i++)
        {
            $last = $salt . pack('N', $i); // $i encoded as 4 bytes, big endian
            $last = $xorsum = mhash($mhash_algorithm, $last, $password); // first iteration
            for ($j = 1; $j < $iterations; $j++) // The other $count - 1 iterations
            {
                $xorsum ^= ($last = mhash($mhash_algorithm, $last, $password));
            }
            $output .= $xorsum;
        }
        return substr($output, 0, $length);
    }
    else
    {
        return false;
    }
}
