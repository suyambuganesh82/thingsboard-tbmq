/**
 * Copyright © 2016-2023 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.mqtt.broker.service.mqtt.client.session;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.thingsboard.mqtt.broker.exception.MqttException;
import org.thingsboard.mqtt.broker.service.stats.StatsManager;
import org.thingsboard.mqtt.broker.session.ClientSessionCtx;

import jakarta.annotation.PostConstruct;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class ClientSessionCtxServiceImpl implements ClientSessionCtxService {

    private final Map<String, ClientSessionCtx> clientContextMap = new ConcurrentHashMap<>();

    private final StatsManager statsManager;
    private final boolean isTraceEnabled = log.isTraceEnabled();

    @PostConstruct
    public void init() {
        statsManager.registerActiveSessionsStats(clientContextMap);
    }

    @Override
    public void registerSession(ClientSessionCtx clientSessionCtx) throws MqttException {
        String clientId = clientSessionCtx.getSessionInfo().getClientInfo().getClientId();
        if (isTraceEnabled) {
            log.trace("Executing registerSession: {}. Current size: {}", clientId, clientContextMap.size());
        }
        clientContextMap.put(clientId, clientSessionCtx);
    }

    @Override
    public void unregisterSession(String clientId) {
        if (isTraceEnabled) {
            log.trace("Executing unregisterSession: {}. Current size: {}", clientId, clientContextMap.size());
        }
        clientContextMap.remove(clientId);
    }

    @Override
    public ClientSessionCtx getClientSessionCtx(String clientId) {
        if (isTraceEnabled) {
            log.trace("Executing getClientSessionCtx: {}", clientId);
        }
        return clientContextMap.get(clientId);
    }

    @Override
    public Collection<ClientSessionCtx> getAllClientSessionCtx() {
        if (isTraceEnabled) {
            log.trace("Executing getAllClientSessionCtx");
        }
        return clientContextMap.values();
    }
}
