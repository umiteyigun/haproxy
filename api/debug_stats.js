const net = require('net');
const client = net.createConnection('/app/sockets/haproxy.sock');
client.on('connect', () => {
    client.write('show stat\n');
});
client.on('data', (data) => {
    console.log(data.toString());
    client.end();
});
client.on('error', (err) => {
    console.error(err);
});
