#pragma once

#include "http/HttpHelper.hpp"

struct Status {
    // Defaults matter: when the check is disabled these stay zeroed and
    // Overlays::RenderNotice() sees an empty notice.
    bool unsafe = false;
    std::string notice;

    int version_current = 0;
    int version_minimum = 0;
};

class Updater {
public:
    ~Updater() = default;
    Updater(const Updater&) = delete;
    Updater(Updater&&) = delete;
    Updater& operator=(const Updater&) = delete;
    Updater& operator=(Updater&&) = delete;

    static bool Init();
    static bool Update(); // Not Implemented Yet
    static bool Process();

    // True when the status check is enabled in config.json
    // ("utils": { "check_updates": true }). Default is off.
    static bool IsEnabled();

    static Status GetStatus();
private:
    Updater() {};

    static Updater& GetInstance()
    {
        static Updater i{};
        return i;
    }

    bool InitImpl();
    bool ProcessImpl();
private:
    Status status;
    bool isSetup = false;
    int current_version = 118;

    // This used to be fetched unconditionally from the *upstream author's*
    // repository on every launch (Updater.cpp:16, called from main.cpp:49).
    // Three problems for a fork:
    //   1. It sends every user's IP and launch time to a repository this project
    //      does not control, for a status the fork does not consume.
    //   2. The version numbers it compares against are upstream's, so a fork
    //      build is permanently "out of date" and shows a modal on every start.
    //   3. An outbound request in the first seconds of startup, tied by URL to
    //      the project name, is a trivially observable fingerprint.
    //
    // Now opt-in via cfg::settings::check_updates (default false). Nothing else
    // depends on it: Process() returns true when disabled, and RenderNotice()
    // simply finds no notice to draw.
    std::string status_url = "https://github.com/IMXNOOBX/cs2-external-esp/raw/refs/heads/main/.github/status.json";
};
