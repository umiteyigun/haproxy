                    break; // Wait for more data
                  }
                  
                  const payload = buffer.slice(8, 8 + payloadSize);
                  
                  // Stream types: 0=stdin, 1=stdout, 2=stderr
                  if (streamType === 1 || streamType === 2) {
                    ws.send(payload.toString());
                  }
                  
                  buffer = buffer.slice(8 + payloadSize);
                }
              }
            });
            
            startRes.on('end', () => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send('\r\n[Connection closed]\r\n');
              }
            });
            
            startRes.on('error', (error) => {
              console.error('Exec stream error:', error);
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(`\r\n[ERROR] Stream error: ${error.message}\r\n`);
              }
            });
          });
          
          currentExecStartReq.on('error', (error) => {
            console.error('Exec start error:', error);
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(`\r\n[ERROR] Exec start error: ${error.message}\r\n`);
            }
          });

          const startPayload = JSON.stringify({
            Detach: false,
            Tty: false
          });
          currentExecStartReq.write(startPayload);
          currentExecStartReq.end();
        } catch (error) {
          console.error('Failed to parse exec create response', error);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(`\r\n[ERROR] Invalid exec response: ${error.message}\r\n`);
          }
          ws.close();
        }
      });

      createExecReq.on('error', (error) => {
        console.error('Exec create error:', error);
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(`\r\n[ERROR] Exec create error: ${error.message}\r\n`);
        }
        ws.close();
      });

      createExecReq.write(JSON.stringify({
        AttachStdin: true,
        AttachStdout: true,
        AttachStderr: true,
        Cmd: ['sh'],
        Tty: false
      }));
      createExecReq.end();
    });

    ws.on('message', (message) => {
      const data = message.toString();
      if (!currentExecId) {
        stdinWriteQueue.push(data);
        return;
      }
      writeStdinToExec(currentExecId, data);
    });

    ws.on('close', () => {
      if (currentExecStartReq) {
        try { currentExecStartReq.destroy(); } catch (_) {}
      }
      if (currentExecId) {
        try {
          const stopReq = http.request({
            socketPath: '/var/run/docker.sock',
            path: `/exec/${currentExecId}/stop`,
            method: 'POST'
          });
          stopReq.on('error', () => {});
          stopReq.end();
        } catch (_) {}
      }
    });
  } catch (error) {
    console.error('Terminal connection error:', error);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(`\r\n[ERROR] ${error.message}\r\n`);
    }
    ws.close();
  }
});