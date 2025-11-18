#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <bits/stdc++.h>
#include <filesystem>
#include <fstream>

#define STB_EASY_FONT_IMPLEMENTATION
#include "stb_easy_font.h"

using namespace std;
namespace fs = std::filesystem;


// ---------- UI CONFIG ----------
constexpr float TITLE_TEXT_SCALE   = 3.2f;
constexpr float DEFAULT_TEXT_SCALE = 2.2f;
constexpr float BUTTON_TEXT_SCALE  = 2.2f;
constexpr float INPUT_TEXT_SCALE   = 2.0f;
constexpr float CREDIT_TEXT_SCALE  = 1.6f;

struct Color { float r,g,b,a; Color(float r=0,float g=0,float b=0,float a=1):r(r),g(g),b(b),a(a){} };

namespace Theme {
    const Color BACKGROUND = Color(0.10f,0.10f,0.12f,1.0f);
    const Color PANEL      = Color(0.15f,0.15f,0.18f,1.0f);
    const Color PANEL_SH   = Color(0,0,0,0.20f);
    const Color BUTTON     = Color(0.20f,0.20f,0.25f,1.0f);
    const Color BUTTON_H   = Color(0.25f,0.25f,0.30f,1.0f);
    const Color BUTTON_A   = Color(0.30f,0.30f,0.35f,1.0f);
    const Color TEXT       = Color(0.92f,0.92f,0.95f,1.0f);
    const Color PLACE      = Color(0.60f,0.60f,0.65f,1.0f);
    const Color INPUT      = Color(0.18f,0.18f,0.22f,1.0f);
    const Color ACCENT     = Color(0.30f,0.60f,0.90f,1.0f);
    const Color SUCCESS    = Color(0.20f,0.70f,0.30f,1.0f);
    const Color ERROR      = Color(0.90f,0.30f,0.30f,1.0f);
}

static void drawFilled(float x,float y,float w,float h, Color c){ glColor4f(c.r,c.g,c.b,c.a); glBegin(GL_QUADS); glVertex2f(x,y); glVertex2f(x+w,y); glVertex2f(x+w,y+h); glVertex2f(x,y+h); glEnd(); }
static void drawOutline(float x,float y,float w,float h, Color c){ glColor4f(c.r,c.g,c.b,c.a); glBegin(GL_LINE_LOOP); glVertex2f(x,y); glVertex2f(x+w,y); glVertex2f(x+w,y+h); glVertex2f(x,y+h); glEnd(); }

struct TextRenderer {
    static void print(const string& t,float x,float y, Color c=Theme::TEXT,float s=DEFAULT_TEXT_SCALE){
        char buf[16000]; int q = stb_easy_font_print(0,0,(char*)t.c_str(),NULL,buf,sizeof(buf));
        glPushMatrix(); glTranslatef(x,y,0); glScalef(s,s,1);
        glColor4f(c.r,c.g,c.b,c.a); glEnableClientState(GL_VERTEX_ARRAY);
        glVertexPointer(2,GL_FLOAT,16,buf); glDrawArrays(GL_QUADS,0,q*4);
        glDisableClientState(GL_VERTEX_ARRAY); glPopMatrix();
    }
    static void bold(const string& t,float x,float y, Color c=Theme::TEXT,float s=CREDIT_TEXT_SCALE){
        print(t,x+1,y+1, Color(0,0,0,c.a*0.5f), s);
        print(t,x,y,c,s);
    }
    static float w(const string& t,float s=DEFAULT_TEXT_SCALE){ return stb_easy_font_width((char*)t.c_str())*s; }
    static float h(const string& t,float s=DEFAULT_TEXT_SCALE){ return stb_easy_font_height((char*)t.c_str())*s; }
};

// ---------- DATA MODEL ----------
class SensitiveData {
public:
    virtual ~SensitiveData() {}
    virtual string getType() const = 0;       // "Password"/"BackupCode"/"QuickNote"
    virtual string getIdentifier() const = 0; // key (service/account/note id)
    virtual string getTitle() const = 0;      // display name on list and detail title
    virtual vector<pair<string,string>> encryptedRows() const = 0;                 // rows to show initially
    virtual vector<pair<string,string>> decryptedRows(const string& key) const = 0;// rows after valid key
    virtual void edit(const string& key,const string& v1,const string& v2="") = 0; // change values
};

static string xorEnc(const string& s){ string r=s; for(char& c:r) c^=3; return r+"!@"; }
static string xorDec(const string& s){ if(s.size()<2) return {}; string r=s.substr(0,s.size()-2); for(char& c:r) c^=3; return r; }
static string safeFile(const string& s){ string o; o.reserve(s.size()); for(char c: s){ if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.') o.push_back(c); else o.push_back('_'); } return o; }

class Password : public SensitiveData {
    string service, user, pwd, encPwd; bool enc;
public:
    Password(const string& svc,const string& u,const string& p,bool e=true):service(svc),user(u),pwd(p),enc(e){ if(enc) encPwd=xorEnc(p); }
    string getType() const override { return "Password"; }
    string getIdentifier() const override { return service; }
    string getTitle() const override { return service; }
    vector<pair<string,string>> encryptedRows() const override { return { {"Username", user}, {"Password", enc? encPwd : pwd} }; }
    vector<pair<string,string>> decryptedRows(const string& key) const override {
        if(enc && key!="turndownforwhat") return { {"Error", "Invalid decryption key."} };
        return { {"Username", user}, {"Password", enc? xorDec(encPwd): pwd} };
    }
    void edit(const string& key,const string& v1,const string& = "") override {
        if(key=="turndownforwhat"){ pwd=v1; if(enc) encPwd=xorEnc(v1); }
    }
};

class BackupCode : public SensitiveData {
    string account, user, code, encUser, encCode; bool enc;
public:
    BackupCode(const string& a,const string& u,const string& c,bool e=true):account(a),user(u),code(c),enc(e){ if(enc){ encUser=xorEnc(u); encCode=xorEnc(c); } }
    string getType() const override { return "BackupCode"; }
    string getIdentifier() const override { return account; }
    string getTitle() const override { return account; }
    vector<pair<string,string>> encryptedRows() const override { return { {"Username", enc? encUser : user}, {"Backup Code", enc? encCode : code} }; }
    vector<pair<string,string>> decryptedRows(const string& key) const override {
        if(enc && key!="turndownforwhat") return { {"Error", "Invalid decryption key."} };
        return { {"Username", enc? xorDec(encUser): user}, {"Backup Code", enc? xorDec(encCode): code} };
    }
    void edit(const string& key,const string& v1,const string& v2="") override {
        if(key=="turndownforwhat"){ user=v1; code=v2; if(enc){ encUser=xorEnc(v1); encCode=xorEnc(v2);} }
    }
};

class QuickNote : public SensitiveData {
    int serial; string note, encNote; bool enc;
public:
    QuickNote(int id,const string& n,bool e=true):serial(id),note(n),enc(e){ if(enc) encNote=xorEnc(n); }
    string getType() const override { return "QuickNote"; }
    string getIdentifier() const override { return to_string(serial); }
    string getTitle() const override { return "Note "+to_string(serial); }
    vector<pair<string,string>> encryptedRows() const override { return { {"Text", enc? "[ENCRYPTED]" : note} }; }
    vector<pair<string,string>> decryptedRows(const string& key) const override {
        if(enc && key!="turndownforwhat") return { {"Error", "Invalid decryption key."} };
        return { {"Text", enc? xorDec(encNote): note} };
    }
    void setEncrypted(bool e){ if(e && !enc) encNote=xorEnc(note); enc=e; }
    bool isEncrypted() const { return enc; }
    void edit(const string& key,const string& v1,const string& = "") override {
        if(key=="turndownforwhat"){ note=v1; if(enc) encNote=xorEnc(v1); }
    }
    int id() const { return serial; }
};

// ---------- STORAGE HELPERS ----------
static string getRowValue(const vector<pair<string,string>>& rows, const string& label){
    for(const auto& p: rows) if(p.first==label) return p.second;
    return "";
}

// ---------- VAULT ----------
class SecureVault {
    string master="ilovetohatethat", key="turndownforwhat";
    vector<unique_ptr<SensitiveData>> items;
    int noteCounter=1;

    // Password files
    fs::path pwDir() const { return fs::path("vault_data")/"Passwords"; }
    fs::path pwPath(const string& svc) const { return pwDir()/(safeFile(svc)+".txt"); }
    // Backup files
    fs::path bcDir() const { return fs::path("vault_data")/"BackupCodes"; }
    fs::path bcPath(const string& acc) const { return bcDir()/(safeFile(acc)+".txt"); }
    // Note files
    fs::path ntDir() const { return fs::path("vault_data")/"Notes"; }
    fs::path ntPath(const string& id) const { return ntDir()/("note_"+safeFile(id)+".txt"); }

    void savePassword(const SensitiveData& it){
        if(it.getType()!="Password") return;
        fs::create_directories(pwDir());
        auto dec = it.decryptedRows(key);
        string name = it.getTitle();
        string user = getRowValue(dec,"Username");
        string pass = getRowValue(dec,"Password");
        ofstream f(pwPath(name), ios::trunc);
        if(!f) return;
        f<<"SERVICE="<<name<<"\n";
        f<<"USERNAME="<<user<<"\n";
        f<<"PASSWORD="<<xorEnc(pass)<<"\n";
        f.flush();
        cout<<"[Saved PW] "<<fs::absolute(pwPath(name)).string()<<endl;
    }
    void saveBackup(const SensitiveData& it){
        if(it.getType()!="BackupCode") return;
        fs::create_directories(bcDir());
        auto dec = it.decryptedRows(key);
        string acc = it.getTitle();
        string user = getRowValue(dec,"Username");
        string code = getRowValue(dec,"Backup Code");
        ofstream f(bcPath(acc), ios::trunc);
        if(!f) return;
        f<<"ACCOUNT="<<acc<<"\n";
        f<<"USERNAME="<<user<<"\n";
        f<<"CODE="<<xorEnc(code)<<"\n";
        f.flush();
        cout<<"[Saved BC] "<<fs::absolute(bcPath(acc)).string()<<endl;
    }
    void saveNote(const SensitiveData& it){
        if(it.getType()!="QuickNote") return;
        fs::create_directories(ntDir());
        auto dec = it.decryptedRows(key);
        string id = it.getIdentifier();
        string text = getRowValue(dec,"Text");
        ofstream f(ntPath(id), ios::trunc);
        if(!f) return;
        f<<"NOTE_ID="<<id<<"\n";
        f<<"TEXT="<<xorEnc(text)<<"\n";
        f.flush();
        cout<<"[Saved NT] "<<fs::absolute(ntPath(id)).string()<<endl;
    }

public:
    bool auth(const string& p) const { return p==master; }
    bool validKey(const string& k) const { return k==key; }
    vector<unique_ptr<SensitiveData>>& all(){ return items; }

    // Add + persist
    void addPassword(const string& s,const string& u,const string& p,bool e=true){
        items.push_back(make_unique<Password>(s,u,p,e));
        savePassword(*items.back());
    }
    void addBackup(const string& a,const string& u,const string& c,bool e=true){
        items.push_back(make_unique<BackupCode>(a,u,c,e));
        saveBackup(*items.back());
    }
    void addNote(const string& n,bool e=true){
        items.push_back(make_unique<QuickNote>(noteCounter++,n,e));
        saveNote(*items.back());
    }

    // Persist after edit
    void savePasswordByService(const string& service){ for(auto& it: items) if(it->getType()=="Password" && it->getIdentifier()==service){ savePassword(*it); break; } }
    void saveBackupByAccount(const string& acc){ for(auto& it: items) if(it->getType()=="BackupCode" && it->getIdentifier()==acc){ saveBackup(*it); break; } }
    void saveNoteById(const string& id){ for(auto& it: items) if(it->getType()=="QuickNote" && it->getIdentifier()==id){ saveNote(*it); break; } }

    // Delete from memory + file
    bool deletePasswordByService(const string& service){
        for(auto it=items.begin(); it!=items.end(); ++it){
            if((*it)->getType()=="Password" && (*it)->getIdentifier()==service){
                std::error_code ec; fs::remove(pwPath(service), ec);
                items.erase(it);
                cout<<"[Deleted PW] "<<fs::absolute(pwPath(service)).string()<<endl;
                return true;
            }
        }
        return false;
    }
    bool deleteBackupByAccount(const string& acc){
        for(auto it=items.begin(); it!=items.end(); ++it){
            if((*it)->getType()=="BackupCode" && (*it)->getIdentifier()==acc){
                std::error_code ec; fs::remove(bcPath(acc), ec);
                items.erase(it);
                cout<<"[Deleted BC] "<<fs::absolute(bcPath(acc)).string()<<endl;
                return true;
            }
        }
        return false;
    }
    bool deleteNoteById(const string& id){
        for(auto it=items.begin(); it!=items.end(); ++it){
            if((*it)->getType()=="QuickNote" && (*it)->getIdentifier()==id){
                std::error_code ec; fs::remove(ntPath(id), ec);
                items.erase(it);
                cout<<"[Deleted NT] "<<fs::absolute(ntPath(id)).string()<<endl;
                return true;
            }
        }
        return false;
    }

    // Loads
    int loadPasswords(){
        int cnt=0; fs::path d=pwDir(); if(!fs::exists(d)) return 0;
        for(auto& e: fs::directory_iterator(d)){
            if(!e.is_regular_file()) continue;
            ifstream f(e.path()); if(!f) continue;
            unordered_map<string,string> m; string line;
            while(getline(f,line)){ auto k=line.find('='); if(k!=string::npos) m[line.substr(0,k)]=line.substr(k+1); }
            string name=m["SERVICE"], u=m["USERNAME"], p=xorDec(m["PASSWORD"]);
            if(!name.empty()){ items.push_back(make_unique<Password>(name,u,p,true)); ++cnt; cout<<"[Loaded PW] "<<fs::absolute(e.path()).string()<<endl; }
        }
        return cnt;
    }
    int loadBackupCodes(){
        int cnt=0; fs::path d=bcDir(); if(!fs::exists(d)) return 0;
        for(auto& e: fs::directory_iterator(d)){
            if(!e.is_regular_file()) continue;
            ifstream f(e.path()); if(!f) continue;
            unordered_map<string,string> m; string line;
            while(getline(f,line)){ auto k=line.find('='); if(k!=string::npos) m[line.substr(0,k)]=line.substr(k+1); }
            string acc=m["ACCOUNT"], u=m["USERNAME"], c=xorDec(m["CODE"]);
            if(!acc.empty()){ items.push_back(make_unique<BackupCode>(acc,u,c,true)); ++cnt; cout<<"[Loaded BC] "<<fs::absolute(e.path()).string()<<endl; }
        }
        return cnt;
    }
    int loadNotes(){
        int cnt=0; fs::path d=ntDir(); if(!fs::exists(d)) return 0;
        for(auto& e: fs::directory_iterator(d)){
            if(!e.is_regular_file()) continue;
            ifstream f(e.path()); if(!f) continue;
            unordered_map<string,string> m; string line;
            while(getline(f,line)){ auto k=line.find('='); if(k!=string::npos) m[line.substr(0,k)]=line.substr(k+1); }
            string id=m["NOTE_ID"], txt=xorDec(m["TEXT"]);
            if(!id.empty()){
                int nid = stoi(id);
                items.push_back(make_unique<QuickNote>(nid,txt,true));
                noteCounter = max(noteCounter, nid+1);
                ++cnt; cout<<"[Loaded NT] "<<fs::absolute(e.path()).string()<<endl;
            }
        }
        return cnt;
    }
};

// ---------- WIDGETS ----------
class Button {
    float x,y,w,h; string text; bool hover=false, press=false;
public:
    function<void()> onClick;
    Button(float X,float Y,float W,float H,string T):x(X),y(Y),w(W),h(H),text(std::move(T)){}
    void render(){
        drawFilled(x+2,y+4,w,h, Theme::PANEL_SH);
        Color c = press? Theme::BUTTON_A : (hover? Theme::BUTTON_H : Theme::BUTTON);
        drawFilled(x,y,w,h,c); drawOutline(x,y,w,h, Color(0.3f,0.3f,0.35f,1));
        float tx = x + (w - TextRenderer::w(text, BUTTON_TEXT_SCALE))/2.0f;
        float ty = y + (h - TextRenderer::h("A", BUTTON_TEXT_SCALE))/2.0f - 2.0f;
        TextRenderer::print(text, tx, ty, Theme::TEXT, BUTTON_TEXT_SCALE);
    }
    bool onMove(float mx,float my){ bool was=hover; hover=(mx>=x&&mx<=x+w&&my>=y&&my<=y+h); return was!=hover; }
    bool onMouse(float mx,float my,bool down){
        if(mx>=x&&mx<=x+w&&my>=y&&my<=y+h){ if(down) press=true; else if(press){ if(onClick) onClick(); press=false; } return true; }
        if(!down) press=false; return false;
    }
};

class TextInput {
    float x,y,w,h; string text, placeholder; bool focus=false, pwd=false;
public:
    function<void()> onEnter; // callback for Enter
    TextInput(float X,float Y,float W,float H,string P=""):x(X),y(Y),w(W),h(H),placeholder(std::move(P)){}
    void setPassword(bool b){ pwd=b; } bool focused()const{ return focus; }
    const string& get()const{ return text; } void set(const string&s){ text=s; } void clear(){ text.clear(); }
    void setOnEnter(function<void()> cb){ onEnter = std::move(cb); }
    void render(){
        drawFilled(x+2,y+4,w,h, Theme::PANEL_SH);
        drawFilled(x,y,w,h, focus? Theme::BUTTON_H: Theme::INPUT); drawOutline(x,y,w,h, focus? Theme::ACCENT: Color(0.3f,0.3f,0.35f,1));
        string disp = text.empty()? placeholder : (pwd? string(text.size(),'*') : text);
        Color c = text.empty()? Theme::PLACE : Theme::TEXT;
        float ty = y + (h - TextRenderer::h("A", INPUT_TEXT_SCALE))/2.0f - 2.0f;
        TextRenderer::print(disp, x+10, ty, c, INPUT_TEXT_SCALE);
        if(focus){ double t=glfwGetTime(); if(fmod(t,1.0)<0.5){
            float cx = x+10+TextRenderer::w(disp, INPUT_TEXT_SCALE);
            glColor4f(Theme::TEXT.r,Theme::TEXT.g,Theme::TEXT.b,0.9f); glBegin(GL_LINES); glVertex2f(cx,y+6); glVertex2f(cx,y+h-6); glEnd();
        }}
    }
    bool click(float mx,float my){ focus=(mx>=x&&mx<=x+w&&my>=y&&my<=y+h); return focus; }
    bool key(int key,int mods){
        if(!focus) return false;
        if((mods&(GLFW_MOD_CONTROL|GLFW_MOD_SUPER)) && key==GLFW_KEY_V){
            const char* clip = glfwGetClipboardString(glfwGetCurrentContext()); if(clip) for(const char*p=clip;*p;++p){ unsigned c=(unsigned char)*p; if(c>=32&&c<=126) text.push_back(char(c)); }
            return true;
        }
        if(key==GLFW_KEY_BACKSPACE && !text.empty()){ text.pop_back(); return true; }
        if((key==GLFW_KEY_ENTER || key==GLFW_KEY_KP_ENTER)){
            if(onEnter) onEnter();
            return true;
        }
        return false;
    }
    bool ch(unsigned cp){ if(!focus) return false; if(cp>=32&&cp<=126){ text.push_back((char)cp); return true; } return false; }
};

// ---------- APP ----------
class App {
    GLFWwindow* win=nullptr; int W=1200,H=800;
    SecureVault vault;
    enum State{
        LOGIN,MENU,PASS_LIST,BC_LIST,NOTES,PASS_DETAIL,BC_DETAIL,NOTE_DETAIL,ADD_NOTE,ADD_PASS,ADD_BC
    } state=LOGIN;

    unique_ptr<TextInput> inPwd,inKey,inNote,inNewUser,inNewCode,inNewPass,inNewSvc,inNewAcc;
    vector<unique_ptr<Button>> btns;

    string selService, selAccount, selNote;
    string keyCache;

    string status; Color statusCol; float statusAlpha=0.0f, statusTTL=0.0f;

public:
    App(){
        // Load from files first
        int loadedPw = vault.loadPasswords();
        int loadedBc = vault.loadBackupCodes();
        int loadedNt = vault.loadNotes();

        // Seed demos only if none exist in that category
        if(loadedPw==0){
            vault.addPassword("Facebook","tijul.kabir.CSE.PUST","fb_pass",true);
            vault.addPassword("Twitter","tijulkabbirtoha","tw_pass");
            vault.addPassword("Instagram","tijul_kabir","ig_pass");
            vault.addPassword("Telegram","Tijul Kabir Toha","tg_pass");
            vault.addPassword("Reddit","Toha","rd_pass");
            vault.addPassword("Discord","KToha","ds_pass");
        }
        if(loadedBc==0){
            vault.addBackup("Gmail","user_gm","backup123");
            vault.addBackup("TryHackMe","tijul_kabir","thm_backup");
            vault.addBackup("HackTheBox","tijul_htb","htb_backup");
        }
        if(loadedNt==0){
            vault.addNote("Plan for CTF challenge for 7 days");
            vault.addNote("Recon phase completed");
        }
    }

    // ---- GLFW init / main loop ----
    bool init(){
        if(!glfwInit()) return false;
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR,2);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR,1);
        glfwWindowHint(GLFW_RESIZABLE,GL_TRUE);
        win = glfwCreateWindow(W,H,"Vault_7",nullptr,nullptr);
        if(!win){ glfwTerminate(); return false; }
        glfwMakeContextCurrent(win);
        if(!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)) return false;
        glfwSwapInterval(1);

        glfwSetWindowUserPointer(win,this);
        glfwSetFramebufferSizeCallback(win, [](GLFWwindow*w,int ww,int hh){
            auto* a=(App*)glfwGetWindowUserPointer(w); a->W=max(1,ww); a->H=max(1,hh);
            glViewport(0,0,a->W,a->H); glMatrixMode(GL_PROJECTION); glLoadIdentity(); glOrtho(0,a->W,a->H,0,-1,1); glMatrixMode(GL_MODELVIEW); glLoadIdentity();
            a->buildUI();
        });
        glfwSetMouseButtonCallback(win, [](GLFWwindow*w,int b,int act,int){
            if(b!=GLFW_MOUSE_BUTTON_LEFT) return; auto* a=(App*)glfwGetWindowUserPointer(w);
            double x,y; glfwGetCursorPos(w,&x,&y); a->mouse((float)x,(float)y, act==GLFW_PRESS);
        });
        glfwSetCursorPosCallback(win, [](GLFWwindow*w,double x,double y){ ((App*)glfwGetWindowUserPointer(w))->onCursorMove((float)x,(float)y); });
        glfwSetKeyCallback(win, [](GLFWwindow*w,int key,int sc,int act,int mods){
            if(!(act==GLFW_PRESS||act==GLFW_REPEAT)) return; ((App*)glfwGetWindowUserPointer(w))->key(key,mods);
        });
        glfwSetCharCallback(win, [](GLFWwindow*w,unsigned int cp){ ((App*)glfwGetWindowUserPointer(w))->ch(cp); });

        glViewport(0,0,W,H); glMatrixMode(GL_PROJECTION); glLoadIdentity(); glOrtho(0,W,H,0,-1,1); glMatrixMode(GL_MODELVIEW); glLoadIdentity();
        glEnable(GL_BLEND); glBlendFunc(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA);

        buildUI();
        return true;
    }

    void run(){ while(!glfwWindowShouldClose(win)){ glfwPollEvents(); update(); render(); } }
    void shutdown(){ glfwDestroyWindow(win); glfwTerminate(); }

    // ---- UI builders ----
    void setStatus(const string& s, Color c, float ttl=2.0f){ status=s; statusCol=c; statusTTL=ttl; statusAlpha=1.0f; }
    void clearInputs(){
        inPwd.reset(); inKey.reset(); inNote.reset(); inNewUser.reset(); inNewCode.reset(); inNewPass.reset();
        inNewSvc.reset(); inNewAcc.reset(); btns.clear();
    }

    void buildUI(){
        clearInputs();
        switch(state){
            case LOGIN:{
                float cx=W*0.5f, cy=H*0.5f;
                inPwd = make_unique<TextInput>(cx-180, cy-20, 360, 54, "Master Password"); inPwd->setPassword(true);
                auto login = make_unique<Button>(cx-90, cy+48, 180, 50, "Login");
                Button* loginPtr = login.get();
                login->onClick=[this]{ if(vault.auth(inPwd->get())){ state=MENU; buildUI(); setStatus("Login successful!", Theme::SUCCESS); } else setStatus("Invalid password!", Theme::ERROR); };
                inPwd->setOnEnter([loginPtr](){ if(loginPtr && loginPtr->onClick) loginPtr->onClick(); });
                btns.push_back(std::move(login));
            } break;

            case MENU:{
                float cx=W*0.5f, start=H*0.5f-140, w=360,h=60,g=20;
                auto add=[&](string t,float y, function<void()> fn){ auto b=make_unique<Button>(cx-w/2,start+y,w,h,t); b->onClick=fn; btns.push_back(std::move(b)); };
                add("Passwords",0,[this]{ state=PASS_LIST; buildUI(); });
                add("Backup Codes",h+g,[this]{ state=BC_LIST; buildUI(); });
                add("Nuclear Launch Codes",2*(h+g),[this]{ state=NOTES; buildUI(); });
                add("Exit",3*(h+g),[this]{ glfwSetWindowShouldClose(win,GL_TRUE); });
            } break;

            case PASS_LIST:{
                auto back=make_unique<Button>(30,30,120,46,"Back"); back->onClick=[this]{ state=MENU; keyCache.clear(); buildUI(); }; btns.push_back(std::move(back));
                auto addBtn=make_unique<Button>(W-220,30,180,46,"Add"); addBtn->onClick=[this]{ state=ADD_PASS; buildUI(); }; btns.push_back(std::move(addBtn));
                float y=140;
                for(auto& it: vault.all()) if(it->getType()=="Password"){
                    auto row=make_unique<Button>(160,y,W-320,50, it->getTitle());
                    string svc=it->getIdentifier();
                    row->onClick=[this,svc]{ selService=svc; state=PASS_DETAIL; buildUI(); };
                    btns.push_back(std::move(row)); y+=64;
                }
            } break;

            case PASS_DETAIL:{
                auto back=make_unique<Button>(30,30,120,46,"Back"); back->onClick=[this]{ state=PASS_LIST; keyCache.clear(); buildUI(); }; btns.push_back(std::move(back));
                auto del=make_unique<Button>(W-170,30,140,46,"Delete");
                del->onClick=[this]{
                    if(vault.deletePasswordByService(selService)){ setStatus("Password site deleted.", Theme::SUCCESS); state=PASS_LIST; buildUI(); }
                    else setStatus("Delete failed.", Theme::ERROR);
                };
                btns.push_back(std::move(del));

                inKey = make_unique<TextInput>(160,H-210,320,50,"Decryption Key");
                auto show=make_unique<Button>(490,H-210,120,50,"Show");
                Button* showPtr = show.get();
                show->onClick=[this]{ keyCache=inKey->get(); };
                inKey->setOnEnter([showPtr](){ if(showPtr && showPtr->onClick) showPtr->onClick(); });
                btns.push_back(std::move(show));

                inNewPass = make_unique<TextInput>(160,H-145,320,50,"New Password");
                auto change=make_unique<Button>(490,H-145,120,50,"Change");
                Button* changePtr = change.get();
                change->onClick=[this]{
                    for(auto& it:vault.all())
                        if(it->getType()=="Password" && it->getIdentifier()==selService)
                            it->edit("turndownforwhat", inNewPass->get());
                    vault.savePasswordByService(selService);
                    setStatus("Password updated!", Theme::SUCCESS);
                };
                inNewPass->setOnEnter([changePtr](){ if(changePtr && changePtr->onClick) changePtr->onClick(); });
                btns.push_back(std::move(change));
            } break;

            // FIX: Add missing Backup Code detail UI to allow decryption and editing
            case BC_DETAIL:{
                auto back=make_unique<Button>(30,30,120,46,"Back");
                back->onClick=[this]{ state=BC_LIST; keyCache.clear(); buildUI(); };
                btns.push_back(std::move(back));

                auto del=make_unique<Button>(W-170,30,140,46,"Delete");
                del->onClick=[this]{
                    if(vault.deleteBackupByAccount(selAccount)){ setStatus("Backup site deleted.", Theme::SUCCESS); state=BC_LIST; buildUI(); }
                    else setStatus("Delete failed.", Theme::ERROR);
                };
                btns.push_back(std::move(del));

                inKey = make_unique<TextInput>(160, H-210, 320, 50, "Decryption Key");
                auto show = make_unique<Button>(490, H-210, 120, 50, "Show");
                Button* showPtr = show.get();
                show->onClick = [this]{ keyCache = inKey->get(); };
                inKey->setOnEnter([showPtr](){ if (showPtr && showPtr->onClick) showPtr->onClick(); });
                btns.push_back(std::move(show));

                inNewUser = make_unique<TextInput>(160, H-145, 200, 50, "New Username");
                inNewCode = make_unique<TextInput>(370, H-145, 200, 50, "New Backup Code");
                auto change = make_unique<Button>(580, H-145, 120, 50, "Change");
                Button* changePtr = change.get();
                change->onClick = [this]{
                    for (auto& it : vault.all()) {
                        if (it->getType() == "BackupCode" && it->getIdentifier() == selAccount) {
                            it->edit("turndownforwhat",
                                     inNewUser ? inNewUser->get() : "",
                                     inNewCode ? inNewCode->get() : "");
                        }
                    }
                    vault.saveBackupByAccount(selAccount);
                    setStatus("Backup code updated!", Theme::SUCCESS);
                };
                inNewUser->setOnEnter([changePtr](){ if (changePtr && changePtr->onClick) changePtr->onClick(); });
                inNewCode->setOnEnter([changePtr](){ if (changePtr && changePtr->onClick) changePtr->onClick(); });
                btns.push_back(std::move(change));
            } break;

            case BC_LIST:{
                auto back=make_unique<Button>(30,30,120,46,"Back"); back->onClick=[this]{ state=MENU; keyCache.clear(); buildUI(); }; btns.push_back(std::move(back));
                auto addBtn=make_unique<Button>(W-220,30,180,46,"Add"); addBtn->onClick=[this]{ state=ADD_BC; buildUI(); }; btns.push_back(std::move(addBtn));
                float y=140;
                for(auto& it: vault.all()) if(it->getType()=="BackupCode"){
                    auto row=make_unique<Button>(160,y,W-320,50, it->getTitle());
                    string acc=it->getIdentifier();
                    row->onClick=[this,acc]{ selAccount=acc; state=BC_DETAIL; buildUI(); };
                    btns.push_back(std::move(row)); y+=64;
                }
            } break;

            case NOTES:{
                auto back=make_unique<Button>(30,30,120,46,"Back");
                back->onClick=[this]{ state=MENU; keyCache.clear(); buildUI(); };
                btns.push_back(std::move(back));

                auto addBtn=make_unique<Button>(W-220,30,180,46,"Add");
                addBtn->onClick=[this]{ state=ADD_NOTE; buildUI(); };
                btns.push_back(std::move(addBtn));

                float y=140;
                for(auto& it: vault.all()) if(it->getType()=="QuickNote"){
                    auto row=make_unique<Button>(160,y,W-320,50, it->getTitle());
                    string nid = it->getIdentifier();
                    row->onClick=[this,nid]{ selNote=nid; state=NOTE_DETAIL; buildUI(); };
                    btns.push_back(std::move(row));
                    y += 64;
                }
            } break;

            case NOTE_DETAIL:{
                auto back=make_unique<Button>(30,30,120,46,"Back"); back->onClick=[this]{ state=NOTES; keyCache.clear(); buildUI(); }; btns.push_back(std::move(back));
                auto del=make_unique<Button>(W-170,30,140,46,"Delete");
                del->onClick=[this]{
                    if(vault.deleteNoteById(selNote)){ setStatus("Note deleted.", Theme::SUCCESS); state=NOTES; buildUI(); }
                    else setStatus("Delete failed.", Theme::ERROR);
                };
                btns.push_back(std::move(del));

                inKey = make_unique<TextInput>(160,H-210,320,50,"Decryption Key");
                auto show=make_unique<Button>(490,H-210,120,50,"Show"); Button* showPtr3 = show.get();
                show->onClick=[this]{ keyCache=inKey->get(); };
                inKey->setOnEnter([showPtr3](){ if(showPtr3 && showPtr3->onClick) showPtr3->onClick(); });
                btns.push_back(std::move(show));

                inNote = make_unique<TextInput>(160,H-145,420,50,"New Note Text");
                auto change=make_unique<Button>(585,H-145,120,50,"Change"); Button* changePtr3 = change.get();
                change->onClick=[this]{
                    for(auto& it:vault.all()) if(it->getType()=="QuickNote" && it->getIdentifier()==selNote) it->edit("turndownforwhat", inNote->get());
                    vault.saveNoteById(selNote);
                    setStatus("Note updated!", Theme::SUCCESS);
                };
                inNote->setOnEnter([changePtr3](){ if(changePtr3 && changePtr3->onClick) changePtr3->onClick(); });
                btns.push_back(std::move(change));
            } break;

            case ADD_NOTE:{
                auto back=make_unique<Button>(30,30,120,46,"Back"); back->onClick=[this]{ state=NOTES; buildUI(); }; btns.push_back(std::move(back));
                float cx=W*0.5f;
                inNote = make_unique<TextInput>(cx-300, H*0.5f, 600, 50, "Enter New Note");
                auto add=make_unique<Button>(cx-70, H*0.5f+60, 140, 50, "Add"); Button* addPtr = add.get();
                add->onClick=[this]{ if(!inNote->get().empty()){ vault.addNote(inNote->get()); setStatus("Note added!", Theme::SUCCESS); state=NOTES; buildUI(); } };
                inNote->setOnEnter([addPtr](){ if(addPtr && addPtr->onClick) addPtr->onClick(); });
                btns.push_back(std::move(add));
            } break;

            case ADD_PASS:{
                auto back=make_unique<Button>(30,30,120,46,"Back"); back->onClick=[this]{ state=PASS_LIST; buildUI(); }; btns.push_back(std::move(back));
                float cx=W*0.5f, cy=H*0.5f-40;
                inNewSvc  = make_unique<TextInput>(cx-240, cy-60, 480, 50, "Service (e.g., Facebook)");
                inNewUser = make_unique<TextInput>(cx-240, cy,     230, 50, "Username");
                inNewPass = make_unique<TextInput>(cx-240+250, cy, 230, 50, "Password");
                auto add=make_unique<Button>(cx-70, cy+70, 140, 50, "Add"); Button* addPtr2 = add.get();
                add->onClick=[this]{
                    if(!inNewSvc->get().empty()){
                        vault.addPassword(inNewSvc->get(), inNewUser?inNewUser->get():"", inNewPass?inNewPass->get():"", true);
                        setStatus("Password site added!", Theme::SUCCESS);
                        state=PASS_LIST; buildUI();
                    } else setStatus("Service is required.", Theme::ERROR);
                };
                inNewSvc->setOnEnter([addPtr2](){ if(addPtr2 && addPtr2->onClick) addPtr2->onClick(); });
                inNewUser->setOnEnter([addPtr2](){ if(addPtr2 && addPtr2->onClick) addPtr2->onClick(); });
                inNewPass->setOnEnter([addPtr2](){ if(addPtr2 && addPtr2->onClick) addPtr2->onClick(); });
                btns.push_back(std::move(add));
            } break;

            case ADD_BC:{
                auto back=make_unique<Button>(30,30,120,46,"Back"); back->onClick=[this]{ state=BC_LIST; buildUI(); }; btns.push_back(std::move(back));
                float cx=W*0.5f, cy=H*0.5f-40;
                inNewAcc  = make_unique<TextInput>(cx-240, cy-60, 480, 50, "Account (e.g., Gmail)");
                inNewUser = make_unique<TextInput>(cx-240, cy,     230, 50, "Username");
                inNewCode = make_unique<TextInput>(cx-240+250, cy, 230, 50, "Backup Code");
                auto add=make_unique<Button>(cx-70, cy+70, 140, 50, "Add"); Button* addPtr3 = add.get();
                add->onClick=[this]{
                    if(!inNewAcc->get().empty()){
                        vault.addBackup(inNewAcc->get(), inNewUser?inNewUser->get():"", inNewCode?inNewCode->get():"", true);
                        setStatus("Backup site added!", Theme::SUCCESS);
                        state=BC_LIST; buildUI();
                    } else setStatus("Account is required.", Theme::ERROR);
                };
                inNewAcc->setOnEnter([addPtr3](){ if(addPtr3 && addPtr3->onClick) addPtr3->onClick(); });
                inNewUser->setOnEnter([addPtr3](){ if(addPtr3 && addPtr3->onClick) addPtr3->onClick(); });
                inNewCode->setOnEnter([addPtr3](){ if(addPtr3 && addPtr3->onClick) addPtr3->onClick(); });
                btns.push_back(std::move(add));
            } break;
        }
    }

    // ---- Input routing ----
    void mouse(float x,float y,bool down){
        for(auto& b:btns) if(b->onMouse(x,y,down)) return;
        if(inPwd && inPwd->click(x,y)) return; if(inKey && inKey->click(x,y)) return;
        if(inNote && inNote->click(x,y)) return; if(inNewUser && inNewUser->click(x,y)) return;
        if(inNewCode && inNewCode->click(x,y)) return; if(inNewPass && inNewPass->click(x,y)) return;
        if(inNewSvc && inNewSvc->click(x,y)) return; if(inNewAcc && inNewAcc->click(x,y)) return;
    }
    void onCursorMove(float x,float y){ for(auto& b:btns) b->onMove(x,y); }
    void key(int key,int mods){
        if(inPwd && inPwd->key(key,mods)) return; if(inKey && inKey->key(key,mods)) return;
        if(inNote && inNote->key(key,mods)) return; if(inNewUser && inNewUser->key(key,mods)) return;
        if(inNewCode && inNewCode->key(key,mods)) return; if(inNewPass && inNewPass->key(key,mods)) return;
        if(inNewSvc && inNewSvc->key(key,mods)) return; if(inNewAcc && inNewAcc->key(key,mods)) return;

        if(key==GLFW_KEY_ESCAPE){
            if(state==MENU) glfwSetWindowShouldClose(win,GL_TRUE);
            else if(state!=LOGIN){ state=MENU; keyCache.clear(); buildUI(); }
        }
    }
    void ch(unsigned cp){
        if(inPwd && inPwd->ch(cp)) return; if(inKey && inKey->ch(cp)) return;
        if(inNote && inNote->ch(cp)) return; if(inNewUser && inNewUser->ch(cp)) return;
        if(inNewCode && inNewCode->ch(cp)) return; if(inNewPass && inNewPass->ch(cp)) return;
        if(inNewSvc && inNewSvc->ch(cp)) return; if(inNewAcc && inNewAcc->ch(cp)) return;
    }

    // ---- Per-frame update & render ----
    void update(){
        if(statusTTL>0){ statusTTL-=0.016f; if(statusTTL<0) statusTTL=0; if(statusTTL<0.6f) statusAlpha=statusTTL/0.6f; }
        else statusAlpha=max(0.0f, statusAlpha-0.02f);
    }

    void renderPanel(){
        drawFilled(0,0,(float)W,96, Theme::PANEL_SH);
        drawFilled(0,0,(float)W,90, Theme::PANEL);
        drawOutline(0,0,(float)W,90, Color(0.25f,0.25f,0.28f,1));
    }

    void renderDetail(const string& type, const string& id){
        for(auto& it: vault.all()){
            if(it->getType()==type && it->getIdentifier()==id){
                string title = it->getTitle();
                float tx = (W - TextRenderer::w(title, TITLE_TEXT_SCALE))*0.5f;
                TextRenderer::print(title, tx, 18, Theme::ACCENT, TITLE_TEXT_SCALE);

                float y = 180.0f;
                for(auto& r: it->encryptedRows()){
                    TextRenderer::print(r.first + ": " + r.second, 160, y, Theme::TEXT, DEFAULT_TEXT_SCALE);
                    y += 40;
                }
                if(!keyCache.empty()){
                    auto dec = it->decryptedRows(keyCache);
                    Color c = (dec.size()==1 && dec[0].first=="Error")? Theme::ERROR : Theme::SUCCESS;
                    y += 8;
                    for(auto& r: dec){
                        string label = (r.first=="Error")? r.first : ("Decrypted " + r.first);
                        TextRenderer::print(label + ": " + r.second, 160, y, c, DEFAULT_TEXT_SCALE);
                        y += 40;
                    }
                }
                break;
            }
        }
    }

    void renderCredits(){
        string l1 = "Inspired by Julian Assange";
        string l2 = "Creator: Tijul Kabir Toha";
        float pad=16;
        float w1 = TextRenderer::w(l1, CREDIT_TEXT_SCALE);
        float w2 = TextRenderer::w(l2, CREDIT_TEXT_SCALE);
        float x = W - pad - max(w1,w2);
        float y = H - pad - TextRenderer::h("A", CREDIT_TEXT_SCALE)*2.0f - 6.0f;
        TextRenderer::bold(l1, x, y, Theme::TEXT, CREDIT_TEXT_SCALE);
        TextRenderer::bold(l2, x, y + TextRenderer::h("A", CREDIT_TEXT_SCALE)+6.0f, Theme::TEXT, CREDIT_TEXT_SCALE);
    }

    void render(){
        glClearColor(Theme::BACKGROUND.r,Theme::BACKGROUND.g,Theme::BACKGROUND.b,Theme::BACKGROUND.a);
        glClear(GL_COLOR_BUFFER_BIT);
        renderPanel();

        switch(state){
            case LOGIN:{
                float cx=W*0.5f;
                string t="VAULT_7";
                TextRenderer::print(t, cx-TextRenderer::w(t,TITLE_TEXT_SCALE)/2.0f, 24, Theme::ACCENT, TITLE_TEXT_SCALE);
                string s="Enter Master Password:";
                TextRenderer::print(s, cx-TextRenderer::w(s)/2.0f, H*0.35f, Theme::TEXT);
            } break;

            case MENU:{
                string t="VAULT_7 - MAIN MENU";
                TextRenderer::print(t, (W-TextRenderer::w(t,TITLE_TEXT_SCALE))/2.0f, 24, Theme::ACCENT, TITLE_TEXT_SCALE);
                renderCredits();
            } break;

            case PASS_LIST:{
                TextRenderer::print("Select a Password Entry",160,110, Theme::ACCENT);
            } break;

            case BC_LIST:{
                TextRenderer::print("Select a Backup Code Entry",160,110, Theme::ACCENT);
            } break;

            case NOTES:{
                TextRenderer::print("QUICK NOTES - NUCLEAR LAUNCH CODES",120,110, Theme::ACCENT);
            } break;

            case PASS_DETAIL: renderDetail("Password", selService); break;
            case BC_DETAIL:   renderDetail("BackupCode", selAccount); break;
            case NOTE_DETAIL: renderDetail("QuickNote", selNote); break;

            case ADD_NOTE:{
                string t="Add a New Note";
                TextRenderer::print(t, W*0.5f-TextRenderer::w(t)/2.0f, H*0.5f-120, Theme::ACCENT);
            } break;

            case ADD_PASS:{
                string t="Add Password Site";
                TextRenderer::print(t, W*0.5f-TextRenderer::w(t)/2.0f, H*0.5f-120, Theme::ACCENT);
            } break;

            case ADD_BC:{
                string t="Add Backup Site";
                TextRenderer::print(t, W*0.5f-TextRenderer::w(t)/2.0f, H*0.5f-120, Theme::ACCENT);
            } break;
        }

        for(auto& b:btns) b->render();
        if(inPwd) inPwd->render(); if(inKey) inKey->render(); if(inNote) inNote->render();
        if(inNewUser) inNewUser->render(); if(inNewCode) inNewCode->render(); if(inNewPass) inNewPass->render();
        if(inNewSvc) inNewSvc->render(); if(inNewAcc) inNewAcc->render();

        if(!status.empty() && statusAlpha>0.01f){
            Color c=statusCol; c.a*=statusAlpha;
            TextRenderer::print(status, 30, H-30, c);
        }
        glfwSwapBuffers(win);
    }
};

int main(){
    using namespace std;
    App app;
    if(!app.init()){ cerr<<"Failed to initialize application\n"; return -1; }
    cout<<"The application is running. Press ESC to exit.\n";
    cout<<"Use the mouse to interact with buttons and text inputs.\n";
    cout<<"Working directory: "<<fs::absolute(".").string()<<endl;
    cout<<"Password files: "<<fs::absolute(fs::path("vault_data")/"Passwords").string()<<endl;
    cout<<"Backup files:   "<<fs::absolute(fs::path("vault_data")/"BackupCodes").string()<<endl;
    cout<<"Notes files:    "<<fs::absolute(fs::path("vault_data")/"Notes").string()<<endl;
    app.run(); app.shutdown();
    return 0;
}