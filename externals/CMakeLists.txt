include(FetchContent)

FetchContent_Declare(
	Zydis
	GIT_REPOSITORY
		https://github.com/zyantific/zydis.git
	GIT_TAG
		master
)

FetchContent_MakeAvailable(Zydis)
