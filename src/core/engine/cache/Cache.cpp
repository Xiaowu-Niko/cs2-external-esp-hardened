#include "Cache.hpp"

#include "core/engine/Engine.hpp" // Circular dep
#include "core/offsets/Dumper.hpp"

bool Cache::Refresh() {
    return Get().RefreshImpl();
}

Snapshot Cache::CopySnapshot() {
    std::lock_guard<std::mutex> lock(Get().mtx);
    return {
        Get().game,
        Get().bomb,
        Get().local,
        Get().globals,
        Get().players
    };
}

bool Cache::RefreshImpl() {
    auto p = Engine::GetProcess();
    auto client = Engine::GetClient();

    if (!p)
        return false;

    auto now = steady_clock::now();

    // The view matrix has to track as fast as possible or the overlay lags the
    // camera, so this one read stays outside the throttle.
    if (!game.Update())
        return false;

    // Everything else is throttled to cfg::settings::refresh_ms.
    //
    // Was a fixed 5 ms, which at 64 players (Player::Update + Weapon::Update
    // are ~15 reads each) is roughly 190,000 NtReadVirtualMemory calls per
    // second. Nothing on screen needs that: 16 ms matches a 60 Hz display and
    // is indistinguishable in use, while cutting the call volume by ~3x.
    // Fewer calls means fewer samples for anything observing the syscall.
    const auto interval = std::chrono::milliseconds(
        cfg::settings::refresh_ms > 0 ? cfg::settings::refresh_ms : 16);

#ifdef _DEBUG
    // Testing performance: let the dev slider win.
    if (now - last < (cfg::dev::cache_refresh_rate * 1ms))
        return true;
#else
    if (now - last < interval)
        return true; // All good
#endif

    game.UpdateEntityList();
    globals.Update();
    bomb.Update();

    std::vector<Player> scan;
    scan.reserve(globals.max_clients);
    for (int i = 0; i < globals.max_clients; i++) {
        auto player = Player(i, game.entity_list, game.list_entry);

        if (!player.Update())
            continue;

        if (player.localplayer)
            this->local = player;

        player.has_c4 = (bomb.carrier != 0 && (uintptr_t)player.pawn_controller_addr == bomb.carrier);

        // TODO: Handle or at least alert, in case of multiple lp
        //if (player.localplayer && (this->local.index == -1 || this->local.index == player.index))
        //    this->local = player;
        //else if (player.localplayer)
        //    LOGF(FATAL, "Offset mismatch, initial({}) current({}) there are more than one local players, update needed", this->local.index, player.index);
    
        scan.push_back(player);
    }

    {
        std::lock_guard<std::mutex> lock(mtx);
        players = std::move(scan);

        duration = duration_cast<std::chrono::milliseconds>(last - now);
        last = now;
    }

    return true;
}
