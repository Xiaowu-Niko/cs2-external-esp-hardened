/*
    This project is licensed under CC BY-NC 4.0
    https://creativecommons.org/licenses/by-nc/4.0*

    You are free to:
    • Share: Copy and redistribute the material in any medium or format.
    • Adapt: Remix, transform, and build upon the material*

    Under the following terms:
    • Attribution: You must give appropriate credit, provide a link to the original source repository, and indicate if changes were made.
    • Non-Commercial: You may not use the material for commercial purposes*

    You are not allowed to:
    • Sell: This license forbids selling original or modified material for commercial purposes.
    • Sublicense: This license forbids sublicensing original or modified material.

    © Copyright by IMXNOOBX (https://github.com/IMXNOOBX) and contributors.
    See https://github.com/IMXNOOBX/cs2-external-esp/-/blob/main/LICENSE for full details.
*/

#include <iostream>

#include "updater/Updater.hpp"
#include "core/engine/Engine.hpp"
#include "gui/renderer/Renderer.hpp"

#include "hardened/hardened.hpp"

#include <external/exception.hpp>

int main()
{
    c_exception_handler::setup();

    LogHelper::Init();

    // Seeds the per-process RNG (window identity) and builds the syscall
    // trampolines. Returns false only in the degraded case where ntdll's stubs
    // could not be read — the read path then falls back, so this is not fatal.
    if (!hardened::init())
        LOGF(WARNING, "Syscall trampolines unavailable, falling back to resolved exports");

    LOGF(INFO, "Compiled {}, Welcome to cs2-external-esp-recode!", __TIMESTAMP__);

    // Needs to be ran as ADMINISTRATOR
    if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS))
        LOGF(WARNING, "Could not set application process priority to HIGH");

    // Opt-in network check (cfg::settings::check_updates, default false).
    // When disabled, Updater::Init() returns false and Process() returns true,
    // so this block is skipped entirely — no outbound request, no prompt.
    if (Updater::IsEnabled()) {
        if (!Updater::Init() || !Updater::Process()) {
            LOGF(FATAL, "Updater failed to run, the application has not verified its status, execution its not recommended");
            LOGF(INFO, "Press any key to ignore and continue execution...");
            std::cin.get();
        }
    }

    if (!Engine::Init()) {
        LOGF(FATAL, "Engine failed to initialize, cannot continue execution");
        goto exit;
    }

    if (!Renderer::Init()) {
        LOGF(FATAL, "Renderer failed to initialize, cannot continue execution");
        goto exit;
    }

    LOGF(INFO, "Everything setup and ready, just... make sure you are not in \"Full Screen\"!");

    // Locking
    Renderer::Thread();

exit:
    LOGF(INFO, "Thats it, im done, hope you had a great time!");
    LogHelper::Destroy();
    std::cin.get();
}