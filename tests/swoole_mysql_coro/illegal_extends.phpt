--TEST--
swoole_mysql_coro: illegal child class
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

class swoole_invalid_mysql_coro extends \Swoole\Coroutine\MySQL
{

    public function __construct()
    {
        // miss parent::__construct
    }

    public function connect(array $server_config = null)
    {
        // miss parent::connect
        return true;
    }

    public function connectRaw(array $server_config)
    {
        return parent::connect($server_config);
    }

    public function __destruct()
    {
        // miss parent::__destruct
    }

}

go(function () {
    $db = new swoole_invalid_mysql_coro;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'strict_type' => true
    ];

    // invalid connect
    assert($db->connect($server));
    assert(!$db->connected);
    assert(!$db->query('select 1'));
    assert($db->errno === SOCKET_ECONNRESET);

    // right implementation
    assert($db->connectRaw($server));
    assert($db->query('select 1')[0][1] === 1);
});

Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
